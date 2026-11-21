# `api_worker` 移行構成案：ECS/Fargate へ実行基盤を移し、既存データと配送先を維持する

**提案は、API とワーカーを別々の ECS/Fargate サービスに移し、既存の S3 バケット・SQS キュー・DynamoDB テーブルを新旧で共用する構成である。** 公開するのは API の HTTPS 入口だけとし、ワーカーは従来どおり SQS を自らポーリングする。データコピーは行わない。切替・切戻しでは、入口の経路だけでなく、API の書込みとワーカーの受信をどちらの環境が担当するかを切り替える。

以下の「既存事実」「要件・承認範囲」は `api_worker.json` の `SYSTEM_DESIGN` に基づく。トップレベルの `requirements` は空だが、同設計内の `constraints` は明示されている。引用する `sources.json` は公式資料の調査メモであり、対象環境の設定、導入承認、実機での成立を証明するものではない。

## 1. 入力理解

| 対象 | 既存事実 | 維持する要件・境界 |
|---|---|---|
| `upload_api` | Kubernetes Deployment 上の Python 3.11 / Linux OCI コンテナ。公開 HTTPS で画像を受け付け、S3 `PutObject`、SQS `SendMessage` を行う。結果照会は DynamoDB `GetItem`。readiness は HTTP `/ready`。観測時のレプリカ数は API の **1 レプリカ**で、API には PVC 参照が観測されていない。 | 外部 API 互換性、公開 HTTPS、登録・照会の挙動を維持する。1 レプリカは移行先の目標値ではない。readiness の HTTP は外部公開の HTTPS とは別のインターフェース。 |
| `image_worker` | Kubernetes Deployment 上の Python 3.11 / Linux OCI コンテナ。受信用 HTTP なし。SQS `ReceiveMessage`、S3 `GetObject`、DynamoDB `PutItem` で、変換ジョブを取得し処理結果を記録する。処理時間は未測定。 | 常駐の非同期コンシューマーと処理結果を維持する。メッセージ削除・可視性延長、変換物の保存形態、ローカル格納の用途はこの記載からは確定しない。 |
| データ・配送 | アップロード先は既存 S3、ジョブの配送先は既存 SQS、状態・結果記録先は既存 DynamoDB。 | 同じリソースを引き継ぎ、アップロードオブジェクトと処理状態を保持する。データ消去や別サービスへの置換は未承認。 |

**承認済みなのはコンテナの再配置と認証方式の変更。** 外部 API や結果の意味を変更する承認ではない。また「AWS接続先以外への外向き通信は未承認」であり、新たな AWS 側の基盤依存先も、必要性・権限・利用可否を確認してから有効化する。

## 2. 提案全体

| 構成要素 | 提案 | 入力根拠・成立条件 |
|---|---|---|
| 公開 API | インターネット向け ALB の HTTPS リスナーから、プライベートサブネットの API タスクへ転送する。既存の公開名・URL・クライアント認証がある場合は互換性を維持する。タスクに公開 IP を付けず、業務ポートへの着信は ALB からに限定する。 | `api.interface: HTTPS / public`、`api.readiness: HTTP /ready`。ALB のターゲットヘルスチェックには HTTP `/ready` を使う案とし、待受ポート、応答コード、公開ルートへの露出有無を実機確認する。業務転送はタスク内 HTTP が既存アプリと通信要件に適合する場合に採用し、内部 TLS が必要ならターゲット側も HTTPS とする設計を確定してから切り替える。証明書、DNS、ALB とタスクの配置、ターゲット登録方式、アップロードやタイムアウトの互換性も導入条件。[Application Load Balancers（S13）](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html)・[Health checks for ALB target groups（S5）](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-health-checks.html) |
| ワーカー | API と別の ECS/Fargate サービスで既存コンテナを常駐実行する。公開 IP、ロードバランサー、受信用 HTTP、業務用着信ルールを設けない。ワーカーから既存 SQS へ HTTPS で接続する。 | `worker.interface: no inbound HTTP`、`SQS ReceiveMessage`。SQS からの配送はワーカーへの HTTP 着信を必要としない。停止時の受信停止と処理中ジョブの扱いは切替前に検証する。[Internetwork traffic privacy in Amazon SQS（S12）](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-internetwork-traffic-privacy.html)・[Amazon SQS visibility timeout（S8）](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html) |
| タスクからの通信 | タスク用サブネットには一般インターネット向けの外向き経路を設けない。既存の S3・DynamoDB へはゲートウェイエンドポイント、既存の SQS へはインターフェイスエンドポイントを使う。公開 ALB の経路とタスクの外向き経路は分離する。 | 「既存データと接続先を引き継ぐ」「AWS接続先以外への外向き通信は未承認」。既存リソースのリージョン、タスク側ルートテーブル、SDK が使うホスト名とプライベート DNS、エンドポイントのセキュリティグループ・ポリシーを照合する。この経路で既存リソースに到達できなければ、移設や公開経路への迂回を前提とせず、通信設計を再レビューする。[Gateway endpoints（S11）](https://docs.aws.amazon.com/vpc/latest/privatelink/gateway-endpoints.html)・[Amazon SQS の通信プライバシー（S12）](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-internetwork-traffic-privacy.html) |
| 起動・運用通信 | 検証済みの同じアプリイメージをプライベート ECR に事前配置し、ECR API/DKR と S3 のレイヤー取得経路で起動する。運用ログは CloudWatch Logs へ送る案とし、画像本体や認証情報は出力しない。 | `runtime: Python 3.11 / Linux OCI container` と外向き通信制約。外部レジストリへの初回取得や起動時ダウンロードには依存させない。選択した Fargate 構成でのイメージ取得、CloudWatch Logs のプライベート経路、DNS、ログの権限・保持設定は導入前に確認する。ログ経路の成立は資料メモだけでは確認済みとしない。[Amazon ECR interface VPC endpoints（S6）](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html)・[Amazon ECS task execution IAM role（S4）](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html) |

## 3. 主体／接続／権限／保存

アプリの認証には API 用・ワーカー用の **ECS タスクロール**を分けて使う。実行ロールはイメージ取得・ログ送信などの基盤用とし、業務データへの権限を持たせない。これは「認証方式の変更は承認済み」と、`api`・`worker` に記録された AWS API 呼出しの差に基づく。クライアント認証をタスクロールで置き換えるものではない。[Amazon ECS task IAM role（S3）](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)・[Amazon ECS task execution IAM role（S4）](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html)

| 呼出主体 | 接続先と許可する操作 | 保存・配送 |
|---|---|---|
| API コンテナ | 既存 S3 に `s3:PutObject`、既存 SQS に `sqs:SendMessage`、既存 DynamoDB に `dynamodb:GetItem`。 | 同じバケットに画像を保存し、同じキューに変換ジョブを登録し、同じテーブルから結果を照会する。 |
| ワーカーコンテナ | 既存 SQS に `sqs:ReceiveMessage`、既存 S3 に `s3:GetObject`、既存 DynamoDB に `dynamodb:PutItem`。SDK やアプリが使う `sqs:DeleteMessage`、`sqs:ChangeMessageVisibility` 等は実際の呼出しを確認したうえで追加する。 | 同じキューから受信し、同じバケットから入力画像を取得し、同じテーブルに処理結果を記録する。SQS の処理完了確認と、S3・DynamoDB の業務データ消去は区別する。 |
| ECS/Fargate 基盤 | 実行ロールで、対象 ECR イメージの取得と、採用するログ送信に必要な操作を行う。アプリから実行ロールを業務資格情報として使わない。 | ECR はイメージ、CloudWatch Logs は運用ログの置き場。どちらも既存の業務データ保存先の代替ではない。 |

権限は実リソースが特定でき次第、バケット内の対象キー範囲・キュー・テーブルに絞り、既存のリソースポリシー、暗号化キーの権限、エンドポイントポリシーとの組合せで検証する。新タスクから許可操作が成功することに加え、不要な書込みが拒否されること、切戻し用の旧主体も引き続き利用できることを確認する。タスクのローカル領域は一時用途に限る。API の PVC 参照が観測されていないことは、両コンテナが永続ファイルを必要としない証明ではない。

## 4. 比較と理由

| 候補 | 評価 |
|---|---|
| **ECS/Fargate：採用案** | `Kubernetes Deployment` で動いている二つの Linux OCI コンテナを、公開 API サービスと常駐ポーリングサービスに分けて再配置できる構成。既存データサービスへの直接呼出しを維持しつつ、アプリ単位のタスクロールに分離でき、Kubernetes クラスタの運用を移行先に持ち込まない。ただし、コンテナの実行要件、終了時の挙動、プライベート起動経路が成立することが条件。[Amazon ECS task IAM role（S3）](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)・[Amazon ECR interface VPC endpoints（S6）](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html) |
| **プライベート EKS：代替案** | 既存 Deployment や Kubernetes 固有の設定を引き継ぎやすい。調査で Kubernetes 固有の依存が判明した場合は有力。一方、現入力ではその依存は示されておらず、閉域のクラスタ管理経路、イメージ配布、Pod の認証・サービス接続を別途設計する必要がある。EKS を選ぶだけで外向き通信制約を満たすわけではない。[Deploy private clusters with limited internet access（S10）](https://docs.aws.amazon.com/eks/latest/userguide/private-clusters.html) |

今回は「コンテナの再配置」と「既存データと接続先の引継ぎ」を優先し、ワーカーをイベント起動型に作り替えたり、保存先を置き換えたりしない。レプリカ数、タスクサイズ、ヘルスチェック間隔、可用性目標は、ALB の採用や API の観測値からは決めない。

## 5. 移行・検証・切戻し

入力根拠は `constraints` の「未処理メッセージ、処理の重複、元データとの照合、切戻し時の配送を確認する」。同じデータリソースを使うためコピーは不要だが、受付・処理・完了確認の途中状態は残る。[Cutover stage（S2）](https://docs.aws.amazon.com/prescriptive-guidance/latest/best-practices-migration-cutover/cutover-stage.html)・[Assess — AWS Well-Architected Migration Lens（S14）](https://docs.aws.amazon.com/wellarchitected/latest/migration-lens/assess-rel.html)・[Amazon SQS at-least-once delivery（S7）](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/standard-queues-at-least-once-delivery.html)・[Amazon SQS visibility timeout（S8）](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html)

1. **事前検証と実施判定。** 旧 API の公開経路、旧 Deployment の復旧設定・認証経路を記録して保持する。新旧で画像登録、メッセージ形式、変換結果、結果照会が互換であることを確認する。実キューの種別、可視性タイムアウト、受信から結果保存・削除までの順序、停止時の動作、再試行・DLQ の有無を確認する。許可された試験で、画像受付から結果照会までと、処理中停止・再配送を検証する。通常のキュー件数や `/ready` だけを合格根拠にしない。
2. **旧側を静止させる。** 承認を得た切替枠で旧 API の新規受付を止め、進行中のリクエストを完了または分類する。次に旧ワーカーの新規受信を停止し、受信済みジョブは完了・結果保存・完了確認まで進める。完了できないものは、再可視化と再処理の安全性を確認できたものだけ引き継ぐ。キューは消去せず、未受信ジョブはそのまま残す。旧タスクの停止・再起動制御を確認し、新旧のワーカーが同時に本番キューを受信しないようにする。
3. **照合して新側を開く。** 既存のオブジェクトキー、メッセージ内容、状態キー、ログなど、実際に対応付けに使える証跡で照合する。特に「S3 保存済み・送信未確認」「受信中・結果未確認」「結果保存済み・削除未確認」を区別する。受信による不可視化は削除ではなく、標準キューなら受信の重複もあり得る。既存の一意 ID や冪等性を仮定せず、結果未確認のジョブを一律再送しない。照合不能な状態を安全に扱えなければ切替を止める。旧側の受信停止を確認して新ワーカーを稼働させ、公開経路を新 ALB に切り替える。経路切替の伝播中も旧 API の書込みは再開しない。受付再開後はアップロード、配送、結果照会、滞留・再試行・重複の兆候を確認する。
4. **切戻しは元の Kubernetes へ行う。** 新 API の新規受付を止め、新ワーカーの受信を止めて、処理中・再可視化待ち・保存済み未削除を同じ基準で照合する。新側の書込みと受信が止まったことを確認したうえで、元の `image_worker` Deployment を同じキューのコンシューマーとして再開し、公開経路を元の `upload_api` Deployment につながる入口へ戻す。切替後に増えた画像・結果・未処理ジョブは既存リソースに残し、旧側で照会・処理できることを確認する。**切替前のスナップショットで上書きせず、完了済みジョブを一括再投入しない。** 新側の更新が旧側で解釈できない、または途中状態を安全に照合できない場合は、経路だけを戻して受付を再開せず、更新を保持したまま復旧判断を行う。

受付停止の許容時間と、停止・照合・再開の手順を事前に合意し、切戻しまでリハーサルする。停止手段や状態を識別する証跡がない場合は、停止機構・照合手段の追加を別途審査し、既存機能として扱わない。

## 6. 未確定事項

| 確定する項目 | 判断への影響 |
|---|---|
| API の公開名・証明書・クライアント認証、現行入口、待受ポート、`/ready` の応答、内部 TLS 要件、アップロード制限とタイムアウト | 公開 API 互換性と ALB 設定。本番に適用するポート・時間・判定値は未確定。 |
| AWS のアカウント・リージョン・リソース識別子、暗号化・ポリシー、イメージ配布元、起動・ログ・秘密情報の依存先 | 既存リソースへの閉域接続、IAM の対象と、タスク起動の成立判定。 |
| 必要処理件数、処理時間の分布、CPU・メモリ・一時領域、ローカル永続化の有無、可用性と復旧目標 | タスクサイズ、API／ワーカー別のレプリカ数、停止猶予、SQS 可視性の設計。 |
| キュー種別・保持設定・再試行・DLQ、完了確認と状態更新の順序、ジョブの照合手段、冪等性・一意 ID の有無、旧側の停止・再開手段 | 未処理ジョブの引継ぎと切戻しの実施可否。受信済みジョブの再配送安全性は未確認。 |

これらは既存の公開範囲や保存先が不明という意味ではない。論理構成は上記に絞り、本番切替の承認は、既存接続先への到達、外部 API・処理結果の互換性、途中状態を含む引継ぎと元環境への切戻しを検証した後とする。