## 入力理解

**移行対象は実行基盤とAWS認証であり、画像・ジョブ・結果の保存先ではない。** `api_worker.json` の `SYSTEM_DESIGN.current` を現行の事実、`system.constraints` を要件として扱う。`sources.json` はサービス仕様に関する調査メモであり、現行設定の証跡でもリソース作成の承認でもない。

| 対象 | 入力から確定する現行の事実 | 値の解釈 |
|---|---|---|
| `upload_api` | Kubernetes Deployment。Python 3.11 / Linux OCIコンテナ。外部からHTTPSで画像を受け付け、S3に保存し、SQSに変換ジョブを投入する。結果照会ではDynamoDBを読む。readinessはHTTP `/ready`。 | `replicas_observed: 1` はこのAPIで観測したレプリカ数1個であり、必要数ではない。`pvc_references_observed: false` はこのAPIでPVC参照が観測されなかったという意味で、全処理がローカル状態に依存しないことの証明ではない。 |
| `image_worker` | 別のKubernetes Deployment。同じくPython 3.11 / Linux OCIコンテナ。受信用HTTPはなく、自らSQSからジョブを受信し、S3から画像を読み、DynamoDBに処理結果を書く。 | `processing_duration: "not measured"` はワーカーの処理時間が未測定という意味。APIのレプリカ数から、ワーカー数、処理時間、可視性タイムアウトは導けない。 |
| 業務データ | アップロード先は既存S3バケット、配送先は既存SQSキュー、状態・結果の保存先は既存DynamoDBテーブル。 | 保存が明示された画像と処理状態を保持する。変換済み画像を別のバケットやファイルシステムに永続化する記載はない。 |

**要件**（`system.constraints`）：承認済みの変更は「コンテナの再配置と認証方式の変更」。外部API互換性、処理結果、APIの外部公開を維持する。既存の3接続先を引き継ぎ、データ消去や別サービスへの置換はしない。ワーカーのHTTP公開は不要で、AWS接続先以外への外向き通信は未承認。切替・切戻しでは未処理、処理中、重複、元データとの照合、配送再開を扱う。

## 提案全体

**提案：Amazon ECS on Fargateに、API用とワーカー用の独立した常駐サービスを置く。** 現行のコンテナと業務操作を保ち、APIはリクエスト待受、ワーカーはキューのポーリングを続ける。両者を一つのタスクに同居させず、起動・停止、必要数、AWS権限を別々に管理する。

```text
外部クライアント ── 既存の公開名・HTTPS ──► 公開ALB ──► 非公開のAPIタスク
                                                       ├─ PutObject   → 既存S3
                                                       ├─ SendMessage → 既存SQS
                                                       └─ GetItem     → 既存DynamoDB

非公開のワーカータスク（受信リスナーなし）
  ├─ ReceiveMessage → 同じ既存SQS   ［応答としてジョブを受信］
  ├─ GetObject      → 同じ既存S3
  └─ PutItem        → 同じ既存DynamoDB
```

- **公開境界**：`current.api.interface: HTTPS / public` と `readiness: HTTP /ready` は別のインターフェースである。公開サブネットにリージョナルALBをAZ配置要件に沿って置き、既存公開名に有効な証明書でHTTPSを終端する案とする。ALBからAPIタスクのIPターゲットへは、アプリが対応し内部区間の要件を満たすことを条件にHTTPで転送する。ヘルスチェックはHTTP `/ready` とし、実際の待受ポート、応答コード、起動・停止時の挙動で成功条件を決める。チェックのために `/ready` を新たに外部公開する必要はない。外部契約、認証、アップロードサイズ・所要時間がALB経由でも維持できることを採用条件とする。資料：[Application Load Balancers][alb]、[Health checks for Application Load Balancer target groups][health]。
- **非公開境界**：両タスクはプライベートサブネットに配置し、公開IPも一般インターネット向け出口も持たせない。APIの受信はALBのセキュリティグループからアプリ・チェック用ポートだけ、ワーカーは業務用の受信許可なしとする。`relations` の「SQS → image_worker」はジョブの流れであり、ネットワーク接続を開始するのは `ReceiveMessage` を呼ぶワーカーである。資料：[Internetwork traffic privacy in Amazon SQS][sqsnet]。
- **成立条件**：両イメージが選択するFargate環境で起動し、既存の起動引数、設定・秘密情報、一時領域、終了処理を再現できること。選択するネットワークモード、IPターゲット登録、サブネット・AZ・IPの余力を実環境で確認する。ALBやタスクを配置すること自体は、処理能力や可用性目標の達成を意味しない。

## 主体/接続/権限/保存

`current.api` および `current.worker` の `reads_aws_apis` / `writes_aws_apis` を権限の起点とする。**アプリにはサービス別のECSタスクロール、起動基盤にはタスク実行ロール**を割り当てる。実行ロールを業務用資格情報にせず、Fargate上でEC2インスタンスプロファイルにも依存しない。資料：[Amazon ECS task IAM role][taskrole]、[Amazon ECS task execution IAM role][execrole]。

| 呼出主体 | 接続先・操作 | 権限境界と保存上の意味 |
|---|---|---|
| APIタスクロール | 既存S3へ `s3:PutObject`、既存SQSへ `sqs:SendMessage` | 実際のアップロード対象オブジェクト範囲と当該キューだけ。従来のオブジェクトキー生成、メッセージ形式、受付応答を保つ。 |
| APIタスクロール | 既存DynamoDBへ `dynamodb:GetItem` | 当該テーブルから結果照会。APIに結果の書込権限は渡さない。 |
| ワーカータスクロール | 既存SQSへ `sqs:ReceiveMessage`、既存S3へ `s3:GetObject` | 当該キューと画像の読取範囲だけ。S3への出力やキューへのジョブ投入は追加しない。 |
| ワーカータスクロール | 既存DynamoDBへ `dynamodb:PutItem` | 当該テーブルに従来と同じキー・形式で結果を記録。既存結果を上書きする条件も実装で確認する。 |
| 起動基盤の実行ロール | 配布用のプライベートECR。`awslogs` を採用する場合は指定ログ出力先 | イメージ取得等の基盤操作に必要な権限のみ。ログやコンテナのローカル領域を画像・結果の正本にしない。 |

**配送完了は別途確認が必要。** 入力にある `ReceiveMessage` だけではメッセージは削除されない。現行コード・SDK設定・実行記録から、結果確定と確認応答の順序、実際の削除主体、失敗時の再配送を確認する。ワーカーが成功後に削除する実装なら、そのロールに当該キューの `sqs:DeleteMessage` を含める。処理中の可視性延長を実際に行うなら `sqs:ChangeMessageVisibility` も対象とする。いずれも現行で確認済みの操作とはしない。資料：[Amazon SQS visibility timeout][visibility]。

**閉域経路の提案**（根拠：`constraints`「既存データと接続先を引き継ぐ」「AWS接続先以外への外向き通信は未承認」）：

- S3とDynamoDBにはゲートウェイエンドポイントを用い、タスクサブネットのルートテーブルと関連付ける。SQSにはインターフェースエンドポイントを用い、プライベートDNSとタスクからのHTTPSを許可する。既存リソースのリージョン、実際の接続名・キューURL、IAM・リソース・エンドポイント各ポリシーの組合せで疎通を確認する。旧Kubernetesからの経路・権限は切戻し期間中も壊さない。資料：[Gateway endpoints — Amazon VPC][gateway]、[Internetwork traffic privacy in Amazon SQS][sqsnet]。
- 配布イメージは事前にプライベートECRに用意し、選択する実行環境に必要なECR API/DKRインターフェースエンドポイントとS3のレイヤー取得経路を用意する。業務バケットだけを許可してレイヤー取得を遮断しない一方、アプリロールに配布用権限を流用しない。外部レジストリへの初回取得や起動時の外部パッケージ取得を前提としない。ログ、秘密情報、暗号鍵は選択した機能ごとに呼出主体・権限・私設経路の要否を確認する。採用する基盤接続先とログ内容の許可を得て、一般向け出口なしでイメージ取得から業務終了まで試験する。資料：[Amazon ECR interface VPC endpoints][ecr]、[Amazon ECS task execution IAM role][execrole]。

## 比較と理由

| 候補 | この案件での評価 | 判断 |
|---|---|---|
| ECS on Fargateで2つの常駐サービス | `current` の「Linux OCI container」と、HTTPS待受／常駐ポーリングの分離を保てる。コンテナごとの業務権限を別タスクロールにでき、Kubernetesクラスタ運用を移行先に持ち込まない。一方、Deploymentの設定とライフサイクルの移植試験が必要。資料：[Amazon ECS task IAM role][taskrole]。 | **採用案**。固有のKubernetes依存がなく、閉域起動・正常終了・負荷試験が成立することが条件。 |
| 非公開構成のAmazon EKSにDeploymentを移設 | `hosting: Kubernetes Deployment` をそのまま生かしやすく、Podやコントローラへの依存が強ければ有利。一方、クラスタ管理経路、ノード／Podの認証、イメージ配布、利用機能別のAWS接続を閉域で成立させる必要がある。資料：[Deploy private clusters with limited internet access — Amazon EKS][eks]。 | 今回は選ばない。Fargateに移せない依存が判明したときの再比較対象。 |

既存キューをイベント起動方式に置き換えず、ワーカー自身が受信する形を選ぶのは、`current.worker` の処理時間が未測定で、配送完了も含む実行契約の変更が承認範囲に含まれていないためである。データ基盤の置換は性能比較の対象ではなく、今回は**未承認**である。

## 移行・検証・切戻し

**単一の既存データ系を両環境が参照し、受付主体と消費主体を順番に引き渡す。** 旧新ワーカーの同時消費や本番ジョブの二重投入を検証手段にしない。根拠は `constraints`「未処理メッセージ、処理の重複、元データとの照合、切戻し時の配送」。受付停止枠と判定責任者を事前に合意する。資料：[Cutover stage — AWS Prescriptive Guidance][cutover]、[Assess — AWS Well-Architected Migration Lens][assess]。

1. **実測・リハーサル**：元のKubernetes両Deployment、イメージ、設定、認証、公開名の現行ルーティング先を記録し、元環境を再開できる状態で保持する。許可された試験データで、同じ入力に対する受付応答、保存画像、ジョブ内容、変換結果、照会応答を比較する。再試行、処理中終了、結果記録の直前・直後の障害も試す。キュー種別、可視性、保持期間、既存の再試行・DLQ設定、処理時間分布と停止に要する時間を確認する。標準キューなら重複配送があり得るが、種別を問わず業務の一回限りの完了は仮定しない。資料：[Amazon SQS at-least-once delivery][delivery]、[Amazon SQS visibility timeout][visibility]。
2. **照合可能な境界を作る**：受付記録、実在するS3キー・必要ならバージョン、メッセージ内容、DynamoDBの実キーと結果のうち、何を対応付けられるかを確認する。新規書込だけでなく同じキーへの更新前後も追える方法を、許可された記録範囲で用意する。キューの可視・不可視件数は監視の補助であり、個々のジョブ完了の証跡ではない。固有ジョブIDや冪等性が存在する前提を置かず、照合不能な処理を止めて判定する手順までリハーサルする。
3. **元環境を静止する**：新ワーカーはまだ消費させない。旧APIの新規アップロード受付を止め、受付済みHTTP要求の応答とS3保存・SQS投入の成否を突き合わせる。旧ワーカーの新規ポーリングを止め、取得済み分は可能なら結果記録・正常な確認応答まで完走させる。終了できなかった処理は不可視のまま残り得るため、結果の有無と再可視化の見込みを記録する。旧Deploymentの自動再開による消費も抑止する。未取得分は既存キューに残し、移送・消去しない。
4. **引渡し・公開切替**：旧消費が止まり、再配送を安全に扱えることを確認して新ワーカーを同じキューに接続する。新APIのターゲット健全性と業務疎通を確認し、既存公開名のルーティングを旧入口からALBへ切り替える。DNS切替を採用する場合はキャッシュで旧入口に到達する間も旧側の書込受付を閉じ、新側だけで再開する。受付・照会の外部互換性、S3実体、キューの滞留・再配送、DynamoDBの結果を切替前の記録と照合する。未解消の欠落・重複、権限不備、互換性不良、合意した運用基準からの逸脱があれば受付／消費を止め、切戻しを判定する。
5. **切戻し先は元のKubernetes環境**：新APIの受付と新ワーカーの新規取得を止め、進行中HTTP、取得済みジョブ、結果記録済みだが削除未確定のジョブを手順3と同様に確定・記録する。切替後に増えたS3画像、SQS配送待ち、DynamoDBの追加・更新結果は同じ保存先に残す。古いスナップショットを一括復元しない。旧APIが新規・更新済み結果を読め、旧ワーカーが新側で投入されたメッセージと画像を扱えることを確認する。下表の未解決分を裁定したうえで、新ワーカー停止を確認し、**元の `image_worker` Deployment** だけに配送を戻す。**元の `upload_api` Deployment** の健全性を確認して公開名を記録済みの旧入口へ戻し、旧側の受付を再開する。旧側から切替中の結果照会と残ジョブの完了まで検証して終了とする。

| 引渡し時の状態（往路・復路共通） | 処置 |
|---|---|
| 未取得、または取得後に未完了で不可視 | 未取得分はそのまま後継の消費主体へ。取得済み分は元の処理が停止したことと副作用の有無を確認し、再可視化後の配送を扱う。見えないことを理由にコピーを投入しない。 |
| 画像保存済みだが投入・受付応答が不明 | 画像だけで未投入と断定しない。受付・送信・結果の証跡とクライアント再試行を照合する。未投入かつ処理対象と確定したものだけ、承認した手順で補送する。 |
| 結果記録済みだが削除不明、または削除済みだが正しい結果を確認できない | 前者は再配送時に二重変換・上書きを起こさず完了扱いできることが条件。後者は自動再配送に頼らず元画像と処理記録から個別に復旧判断する。対応関係が曖昧なら一括再投入・一括削除をせず消費を保留する。 |

## 未確定事項

| 本番移行前に確定する事項 | 判断への影響 |
|---|---|
| 外部API契約・認証、既存公開名と切替権限、証明書、内部転送条件、`/ready` のポート・成功条件 | 公開HTTPSとHTTP `/ready` の存在は確定。ALBでの互換性と、元の入口へ戻す操作は実証が必要。 |
| イメージのCPUアーキテクチャ、リソース使用量、一時ディスク・Kubernetes機能への依存、秘密情報、停止時のポーリング制御 | タスク定義と安全な引渡しの成立条件。 |
| 既存3リソースの識別子・リージョン、キー／メッセージ形式、暗号化、ポリシー、必要な基盤接続先 | 接続先の種類と業務操作は確定。最小権限、閉域経路、旧新双方からの互換性は実値で検証する。 |
| 受付と投入の整合、結果確定と削除の主体・順序、重複時の副作用、照合可能な記録 | 黙って権限を追加したり冪等とみなしたりしない。安全な停止・照合・再配送が実証できなければ本番切替を行わず、必要な変更を別途承認に付す。 |
| 必要件数、API／ワーカー別の必要タスク数、処理・可視性・停止の各時間、可用性・復旧目標、許容停止枠 | 実測と業務合意後に容量、各タイムアウト、切替・切戻しの判定値を定める。観測レプリカ数を代入しない。 |

[alb]: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html
[health]: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-health-checks.html
[sqsnet]: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-internetwork-traffic-privacy.html
[taskrole]: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
[execrole]: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html
[gateway]: https://docs.aws.amazon.com/vpc/latest/privatelink/gateway-endpoints.html
[ecr]: https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html
[eks]: https://docs.aws.amazon.com/eks/latest/userguide/private-clusters.html
[visibility]: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
[delivery]: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/standard-queues-at-least-once-delivery.html
[cutover]: https://docs.aws.amazon.com/prescriptive-guidance/latest/best-practices-migration-cutover/cutover-stage.html
[assess]: https://docs.aws.amazon.com/wellarchitected/latest/migration-lens/assess-rel.html