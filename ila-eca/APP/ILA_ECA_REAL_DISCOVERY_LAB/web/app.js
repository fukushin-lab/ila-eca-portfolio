'use strict';
/* RECORD_VIEW_START: presentation only; never changes persisted decisions. */
const RecordView=(()=>{
 const reasonTexts={
  MODEL_CONNECTION_NOT_CONFIGURED_NO_CALL_SENT:'生成用の接続が未設定のため、処理を保留しました。モデルは呼び出していません。',
  LOCAL_MODEL_NOT_ENABLED:'生成用の接続が有効になっていないため、調査を保留しました。',
  MODEL_REQUESTED_INFORMATION:'モデルは、判断に必要な情報が不足しているため保留を選びました。',
  INITIAL_INTAKE_NOT_CAUSE_CONFIRMATION:'障害の報告を受け付けた段階です。原因の確認はこれからです。',
  EXECUTION_BUDGET_REACHED_NOT_RESOLVED:'設定された調査・判断の回数上限に達したため、制御側で停止しました。',
  EVALUATION_SLOT_REQUIRED_BEFORE_NEW_READ:'新しい調査結果を評価するための呼出し枠を確保できず、調査前に停止しました。',
  DUPLICATE_INVESTIGATION_REQUIRES_REASON:'同じ条件の調査が実施済みのため、繰り返さずに停止しました。',
  READ_ADAPTER_UNAVAILABLE:'選択した読み取り調査を実行する接続が利用できません。',
  MODEL_FAILURE_REVIEW_REQUIRED:'回答または呼出しを正常に確認できず、調査を停止しました。原因の切り分けが必要です。',
  READ_RESULT_REJECTED_REVIEW_REQUIRED:'取得結果が検査を通らなかったため、その結果を採用せずに停止しました。',
  OLLAMA_FINAL_NOT_JSON:'モデルの回答が受理できる形式になっていないため、回答の読取りで停止しました。',
  ROUTE_MODEL_INCOMPLETE:'回答が最後まで完了していないため、そのまま採用せずに停止しました。',
  MODEL_INTERRUPTED_RESULT_UNKNOWN:'呼出しの途中で処理が中断され、完了したか確認できません。',
  TRANSPORT_RESULT_UNKNOWN:'通信が途切れ、送信先で処理が完了したか確認できません。',
  PROCESS_INTERRUPTED_EXPLICIT_RECONCILIATION_REQUIRED:'前の実行が途中で中断され、完了したか確認できません。',
  ACCEPTED_COMMAND_HAS_NO_EXECUTION_EVENT_NO_RESEND:'要求の受付は記録されていますが、その後の実行記録を確認できません。',
  SAVED_RESULT_ONLY_NO_AUTOMATIC_RESEND:'保存済みの記録を確認しました。再送は行っていません。',
  ONLY_INTERRUPTED_JOB_RECONCILIATION_ALLOWED:'この照合は、途中で中断した実行の確認に使います。',
  EXISTING_BASELINE_REQUIRED_FOR_NO_OP:'比較に使う既存の基準構成がないため、変更不要とは判定できません。',
  EXISTING_APPROVED_CHANGE_REQUIRED:'作業計画の対象となる、既存の承認済み変更が必要です。',
  FULL_B_APPROVED_LAB_CHANGE_REQUIRED:'対象の変更について、既存の承認条件が満たされていません。',
  COLLABORATION_CONNECTION_NOT_CONFIGURED:'外部ツールとの接続設定がないため、処理を開始できませんでした。',
  SERVICE_SCOPE_PERMISSION_OR_EXPIRY_DENIED:'対象範囲・操作権限・有効期限のいずれかが接続条件を満たしていません。',
  SERVICE_EXPORT_PACKET_NOT_AUTHORIZED:'この版の資料について、外部への送信許可を確認できませんでした。',
  HTTP_401:'接続先で認証を確認できませんでした。',
  HTTP_403:'接続先でこの操作が許可されませんでした。',
  STALE_DOCUMENT_VERSION_RELOAD_REQUIRED:'新しい版が保存されているため、表示中の版では処理を進められません。',
  SUBMISSION_REVISION_IS_NOT_CURRENT:'選択した成果物が最新の版ではないため、提出を止めました。',
  UNAPPROVED_MODEL_REPAIR_CANDIDATE:'根拠付きの修復候補が保存されています。承認と修復の実行はこれからです。',
  NO_CURRENT_GITLAB_APPROVAL:'この照合では、現在の対象版に有効な正式承認を確認できませんでした。',
  CURRENT_GITLAB_DESIGN_APPROVAL_VERIFIED:'保存された照合時点で、対象版に結び付く正式承認を確認しました。',
  CURRENT_GITLAB_ACCOUNT_TEST_APPROVAL_VERIFIED:'保存された照合時点で、検証用アカウントの承認反映を確認しました。',
  USER_REQUESTED_STOP:'利用者から中断の要求を受け付けました。',
  USER_STOP_BEFORE_EXECUTION:'実行を始める前に、利用者の要求で停止しました。',
  USER_REQUESTED_STOP_BETWEEN_INVESTIGATION_STEPS:'調査の区切りで、利用者の要求により停止しました。',
  MEETING_TEXT_OR_FILE_REQUIRED:'解析する会議本文がありません。文字起こし・録音を選ぶか、会議本文を入力してください。',
  SELECT_ONE_MEETING_INPUT:'保存資料と直接入力のどちらか一つを選んでください。',
  STOPPED_AFTER_CURRENT_CALL_RESULT_RETAINED:'現在の処理結果を保存し、以降の処理を停止しました。'
 };
 const routeNames={A:'設計案を作成',B:'承認済み変更の作業計画を作成',C:'障害を調査',D:'資料への質問に回答',E:'会議内容を解析',F:'既存の構成・状態を確認',G:'AWSの設計案を作成・改訂',H:'セキュリティ上の報告を調査'};
 const operationNames={save_request:'依頼内容を保存',ingest:'資料を保存・取り込み',reconcile:'保存済みの結果を照合',google_sync:'Googleの会議予定を取得',google_collect:'会議の記録資料を取得',drive_import:'Driveから資料を取得',meeting_analyze:'保存した会議資料を解析',gitlab_prepare:'レビューへ提出する資料を準備',gitlab_submit:'GitLabのレビューへ提出',gitlab_refresh:'GitLabのレビュー状況を確認',gitlab_reconcile:'GitLabへの提出結果を照合',formal_status:'正式承認の状態を照合',formal_prepare:'承認担当者へレビューを回付'};
 const oldNames={'業務処理':'run','保存状態からの再開':'resume','資料の取込み':'ingest','結果の照合':'reconcile','GitLab提出':'gitlab_submit','送信対象の準備':'gitlab_prepare','レビュー状態の取得':'gitlab_refresh','正式承認の照合':'formal_status'};
 const stateNames={QUEUED:'受付済み・実行待ち',RUNNING:'処理中',FINISHED:'結果を保存済み',FAILED:'処理を完了できず停止',HOLD:'保留',WAITING_INFORMATION:'追加情報待ち',AWAITING_REVIEW:'レビュー待ち',WAITING_REPAIR:'修復候補・承認待ち',CANCELED:'利用者の要求で中断',STOP_REQUESTED:'中断要求を受付',RESULT_UNKNOWN:'結果不明・照合が必要',CONTROL_STOP:'設定上限で停止'};
 const eventTexts={QUEUED:'要求を受け付けました。',RUNNING:'処理を開始しました。',FINISHED:'処理結果を保存しました。',FAILED:'完了できずに停止し、理由を記録しました。',STOP_REQUESTED:'利用者の中断要求を記録しました。',CANCELED:'処理の中断を記録しました。'};
 const limits=new Set(['EXECUTION_BUDGET_REACHED_NOT_RESOLVED','EVALUATION_SLOT_REQUIRED_BEFORE_NEW_READ']);
 const uncertain=new Set(['TRANSPORT_RESULT_UNKNOWN','MODEL_INTERRUPTED_RESULT_UNKNOWN','PROCESS_INTERRUPTED_EXPLICIT_RECONCILIATION_REQUIRED','ACCEPTED_COMMAND_HAS_NO_EXECUTION_EVENT_NO_RESEND']);
 function layers(r){const out=[];function visit(x){if(!x||typeof x!=='object'||Array.isArray(x))return;out.push(x);for(const k of ['result','call','validation_failure'])visit(x[k]);}visit(r);return out;}
 function texts(r,key){return [...new Set(layers(r).flatMap(x=>typeof x[key]==='string'&&x[key]?[x[key]]:[]))];}
 function flag(r,key){return layers(r).some(x=>x[key]===true);}
 function freeReason(s){return typeof s==='string' && !/^[A-Za-z_][A-Za-z0-9_.:/-]*$/.test(s);}
 function explainReason(code){return reasonTexts[code]||(freeReason(code)?code:'この記録だけでは理由を文章で説明できません。診断用の記録に原文を残しています。');}
 function creationLabel(mode){return ({MOCK:'模擬試験',NOT_CONFIGURED:'生成接続を設定していない実行',LOCAL_MODEL:'ローカル生成の設定で実行',LIVE_COMPARISON_ASTRA_SYNTHETIC_ONLY:'Astra実接続の比較試験（合成資料）',LIVE_COMPARISON_ASTRA_AUTH_RECOVERY_SAME_CASE:'認証更新後のAstra比較試験',UNKNOWN_HISTORICAL_RECORD:'作成時の実行区分は未記録'})[mode]||'実行区分は記録を確認';}
 function present(job,route){
  const r=job.result_summary||{}, op=job.operation||oldNames[job.operation_label]||job.operation_label;
  const codes=[...new Set([job.reason,...texts(r,'reason'),...texts(r,'error_code')].filter(Boolean))];
  let status=job.result_category||job.state;
  if(codes.some(c=>uncertain.has(c)))status='RESULT_UNKNOWN';
  else if(codes.some(c=>limits.has(c)))status='CONTROL_STOP';
  else if(codes.includes('MODEL_REQUESTED_INFORMATION'))status='WAITING_INFORMATION';
  const title=op==='run'?(routeNames[route]||'依頼された処理を実行'):op==='resume'?(route==='C'?'保存状態から障害調査を再開':'保存状態から処理を再開'):(operationNames[op]||'依頼された処理を実行');
  const mode=job.mode||(['QUEUED','RUNNING','STOP_REQUESTED'].includes(job.state)?job.display_mode:null);
  let result='',next='成果物と記録を確認してください。';
  if(status==='RESULT_UNKNOWN'){result='処理が完了したか確認できていません。';next='保存済みの結果を照合してから、再開するか判断してください。自動再送は行いません。';}
  else if(status==='CONTROL_STOP'){result='設定された実行枠に達したため、制御側で停止しました。';next='保存済みの調査結果と残りの実行枠を確認してください。続ける場合は既存の明示的な再開操作を使います。';}
  else if(status==='QUEUED'){result='要求を受け付け、順番に実行するため保存しました。';next='この記録から実行状態を確認できます。再度ボタンを押す必要はありません。';}
  else if(status==='RUNNING'){result='保存した要求を処理しています。';next='結果が記録されるまでお待ちください。この画面を閉じても受付記録は残ります。';}
  else if(status==='STOP_REQUESTED'){result='中断の要求を受け付けました。';next='実行中の処理がある場合は結果を保存してから止まります。停止の記録を確認してください。';}
  else if(status==='CANCELED'){result=job.outcome==='STOPPED_AFTER_CURRENT_CALL_RESULT_RETAINED'?reasonTexts.STOPPED_AFTER_CURRENT_CALL_RESULT_RETAINED:'利用者の要求で処理を停止しました。';next='保存された結果と未完了の範囲を確認し、必要な場合だけ明示的に再開してください。';}
  else if(status==='FAILED'){result='処理を完了できず、停止しました。';next='記録された理由を確認してください。説明が足りない場合は診断用の記録を管理者へ伝えてください。';}
  else if(status==='WAITING_INFORMATION'||job.outcome==='HOLD'){result='処理を保留しています。';next=codes.includes('MODEL_CONNECTION_NOT_CONFIGURED_NO_CALL_SENT')||codes.includes('LOCAL_MODEL_NOT_ENABLED')?'管理者の接続設定が必要です。入力と保存記録はそのまま利用できます。':'不足している資料や条件を確認してください。追加資料を入れた場合は、既存の明示的な再開・改訂操作を使います。';}
  else if(job.outcome==='AWAITING_REVIEW'){status='AWAITING_REVIEW';result='設計案を保存しました。レビューはこれからです。';next='成果物の内容・根拠・未知事項を確認し、既存のレビュー経路へ進めてください。';}
  else if(job.outcome==='WAITING_REPAIR'){status='WAITING_REPAIR';result='修復候補を保存し、承認を待っています。';next='影響・検証・切戻しを確認して既存の承認経路へ進めます。修復は実行していません。';}
  else if(job.outcome==='INPUT_SAVED'){result='依頼内容を保存しました。解析・生成・外部送信は行っていません。';next='必要な資料を追加し、準備ができたら実行してください。';}
  else if(job.outcome==='IMPORTED'){result='資料の保存・取込みを終えました。';next='入力資料の一覧を確認してください。会議資料の解析は別の操作で行えます。';}
  else if(job.outcome==='PLANNED_UNEXECUTED'){result='承認済み変更の作業計画を保存しました。作業は未実施です。';next='計画をレビューし、既存の実行手続きに従ってください。';}
  else if(op==='formal_status'){
   if(flag(r,'test_approval_granted')){result='記録された照合時点で、検証用アカウントの承認反映を確認しました。';next='これはテスト承認の記録です。実運用の正式承認としては利用できません。';}
   else if(flag(r,'formal_approval_granted')){result='記録された照合時点で、対象版の正式承認を確認しました。';next='現在の版への有効性は、実行前に既存の承認経路で再確認してください。';}
   else{result='この照合では、有効な正式承認を確認できませんでした。';next='対象版・担当者・既存の承認条件を確認してください。MR作成やCI成功だけでは正式承認になりません。';}
  }
  else if(op==='gitlab_prepare'){result='レビューへ提出する成果物と版の確認結果を保存しました。';next='既存の送信許可を確認してから、Draft MRへの提出を操作してください。';}
  else if(op==='gitlab_submit'){result='GitLabのレビュー用MRへの提出を確認し、記録しました。';next='MRリンクからレビュー状況を確認してください。正式承認の状態は別に照合します。';}
  else if(op==='gitlab_refresh'){result='GitLabから取得したレビュー状況を保存しました。';next='レビュー状況と正式承認を区別して確認してください。';}
  else if(op==='formal_prepare'){result='既存の承認担当者への回付結果を保存しました。';next='指定された担当者のレビューと、既存の承認通知の反映を確認してください。';}
  else if(op==='google_sync'){result='指定した範囲の会議予定について、取得結果を保存しました。';next='案件に関連付いた会議を確認し、必要な記録資料を選んでください。';}
  else if(['google_collect','drive_import'].includes(op)){result='会議資料の取得処理の結果を保存しました。';next='取得できた資料と取得できなかった資料を確認してください。Drive取得とMeetによる記録生成は別の確認です。';}
  else if(job.outcome==='GENERATED'){result=route==='E'||op==='meeting_analyze'?'会議内容の解析結果を保存しました。':route==='G'?'AWSの設計案を保存しました。':'回答・判断の結果を保存しました。';next='成果物を開いて内容と根拠を確認してください。保存完了は、内容の正しさや正式承認の証明ではありません。';}
  else if(job.outcome==='RECONCILED_SAVED_RESULT'||op==='reconcile'){result='保存済みの結果を照合しました。';next='記録された結果と、引き続き確認が必要な範囲を確認してください。新しい生成は行っていません。';}
  else{result='この処理の結果を保存しました。';}
  const known=codes.find(c=>reasonTexts[c]), original=codes.find(freeReason);
  let reason=known?explainReason(known):original||(['FAILED','WAITING_INFORMATION','CONTROL_STOP'].includes(status)?'詳しい理由は、診断用の記録と成果物で確認してください。':'');
  if(mode==='MOCK'&&known==='MODEL_REQUESTED_INFORMATION')reason='模擬の判断処理は、情報不足を理由に保留を選びました。';
  const missing=[...new Set(layers(r).flatMap(x=>Array.isArray(x.missing)?x.missing.filter(v=>typeof v==='string'):[]))];
  const unavailable=layers(r).flatMap(x=>Array.isArray(x.unavailable)?x.unavailable:[]);
  if(unavailable.length&&job.state==='FINISHED'&&!['FAILED','RESULT_UNKNOWN','CONTROL_STOP','CANCELED'].includes(status)){result='資料取得の結果を保存しました。一部の資料には未取得の記録があります。';next='取得できなかった理由を確認してください。未取得を資料や原因の不存在とは扱いません。';}
  return {title,status,statusLabel:stateNames[status]||'記録を保存',result,reason,next,missing,
   modeLabel:mode?creationLabel(mode):'保存された実行記録',
   history:(job.events||[]).map(e=>({label:eventTexts[e.state]||'状態の変化を記録しました。',note:e.reason?explainReason(e.reason):''}))};
 }
 function summaryText(r){
  if(flag(r,'test_approval_granted'))return '検証用アカウントの承認反映を確認した記録です。実運用の正式承認ではありません。';
  if(flag(r,'formal_approval_granted'))return '保存された照合時点では、対象版の正式承認を確認しています。現在の有効性は再照合が必要です。';
  const reasons=texts(r,'reason').concat(texts(r,'error_code'));
  if(reasons.length)return [...new Set(reasons.map(explainReason))].join(' ');
  if(layers(r).some(x=>x.formal_approval_granted===false))return 'この照合では正式承認を確認できていません。';
  return '照合結果の詳細を確認してください。';
 }
 function documentLabel(d){return d.native_lifecycle?'変更対象の設計書':({LLM_NON_AWS_DESIGN:'非AWSの設計案',AWS_LOCAL_DESIGN:'AWSの設計案',FULL_ROUTE_DRAFT:'処理結果の報告書',INCIDENT_INVESTIGATION:'障害調査の報告書',SAVED_REVIEW_SUBMISSION:'レビューへの提出資料'})[d.document_kind]||'保存された成果物';}
 function documentProjection(data){
  const sections=[], array=x=>Array.isArray(x)?x:[], strings=x=>array(x).filter(x=>typeof x==='string'), section=(heading,paragraphs=[],entries=[])=>sections.push({heading,paragraphs:paragraphs.filter(x=>typeof x==='string'&&x),entries});
  const fieldNames={symptom:'症状',status:'状態',state:'状態',message:'メッセージ',error:'エラー',coverage:'確認した範囲',reason:'理由',value:'値',values:'取得した値',target_ref:'対象',observed_at:'記録された時刻',depends_on:'依存先',sampled_response:'取得した応答',sampled_authentication:'取得した認証状態'};
  function valueLines(v,label='',depth=0){
   if(typeof v==='string')return [label?label+'：'+v:v];
   if(v===null)return [label+'：null（保存された値）'];
   if(typeof v==='boolean')return [label+'：'+(v?'真（true）':'偽（false）')];
   if(typeof v==='number')return [label+'：'+(Number.isSafeInteger(v)?String(v):'数値が記録されています。正確な表記は原文で確認してください。')];
   if(depth>=4)return [label+'：詳細な構造は原文で確認してください。'];
   if(Array.isArray(v))return v.length?v.flatMap((x,i)=>valueLines(x,label+' '+(i+1),depth+1)):[label+'：この配列に記録された項目はありません。'];
   if(v&&typeof v==='object')return Object.entries(v).flatMap(([k,x])=>valueLines(x,(label?label+' / ':'')+(fieldNames[k]||k),depth+1));
   return [];
  }
  const hStatus=x=>({OPEN:'検討中',SUPPORTED:'支持する根拠あり（モデルの評価）',CONTRADICTED:'反する根拠あり（モデルの評価）',UNCERTAIN:'判断材料が不足'})[x]||'分類の詳細は原文に記録';
  const phases={DISCOVERY:'事前調査',IMPLEMENTATION:'実施案',VERIFICATION:'独立確認',ROLLBACK:'切戻し'};
  const modeNames={INVESTIGATE:'追加の読み取り調査を選択',HOLD:'不足情報を示して保留',PROPOSE_REPAIR:'未承認の修復候補を提示'};
  const snapshot=data.snapshot;
  if(data.schema==='ila.eca.incident-investigation-report.v1'&&snapshot){
   const facts=array(data.facts), factNames=new Map(facts.map((f,i)=>[f.fact_ref,'根拠'+(i+1)]));
   const references=(label,refs)=>strings(refs).length?[label+'：'+strings(refs).map(id=>factNames.get(id)||'原文の参照情報を確認').join('、')]:[];
   const decisions=array(data.decisions).map((d,i)=>{const a=d.proposal?.assessment||{},inv=a.investigation||{};return {title:'判断'+(i+1)+'：'+(modeNames[a.next_mode]||'判断の記録'),lines:[a.summary,...array(a.hypotheses).flatMap(h=>['仮説：'+h.explanation,'評価：'+hStatus(h.status),...(h.update_reason?['見直した理由：'+h.update_reason]:[]),...references('支持する根拠',h.support_refs),...references('反する根拠',h.counter_refs)]),inv.information_needed?'次に求めた情報：'+inv.information_needed:'',inv.reason?'調査を選んだ理由：'+inv.reason:'',...array(inv.outcomes).map(o=>'想定される結果「'+o.result+'」の場合：'+o.interpretation),...strings(a.missing).map(x=>'不足している情報：'+x)].filter(Boolean)};});
   const latest=array(data.decisions).at(-1)?.proposal?.assessment||{};
   section('この版で分かること',[snapshot.incident?.symptom,explainReason(snapshot.reason),'調査や判断の記録は、原因の正しさ・正式承認・復旧の確認と分けて扱います。']);
   const at=value=>{const date=new Date(value);return typeof value==='string'&&!Number.isNaN(date.getTime())?new Intl.DateTimeFormat('ja-JP',{timeZone:'Asia/Tokyo',dateStyle:'medium',timeStyle:'medium'}).format(date)+'（日本時間）':'時刻の詳細は原文で確認してください。';};
   section('対象と記録された時刻',['登録された対象：'+array(snapshot.incident?.targets).length+'件',snapshot.incident?.occurred_at?'報告された発生時刻：'+at(snapshot.incident.occurred_at):'',snapshot.incident?.window?'調査対象の時間帯：'+at(snapshot.incident.window.start)+' ～ '+at(snapshot.incident.window.end):'']);
   if(array(data.model_runs).some(r=>/MOCK|SCRIPTED/.test(r.origin||'')))section('実行の区分',['この報告書には、模擬の判断処理による記録が含まれています。実モデルの品質確認としては扱いません。']);
   section('現在の仮説',array(snapshot.hypotheses).length?[]:['この版には、仮説が登録されていません。'],array(snapshot.hypotheses).map(h=>({title:h.explanation,lines:['評価：'+hStatus(h.status),h.update_reason?'変更した理由：'+h.update_reason:'',...references('支持する根拠',h.support_refs),...references('反する根拠',h.counter_refs),...strings(h.missing).map(x=>'不足している情報：'+x)].filter(Boolean)})));
   if(array(snapshot.retired).length)section('撤回した仮説',[],array(snapshot.retired).map(h=>({title:'仮説を撤回',lines:[h.reason,...references('撤回の根拠',h.counter_refs)]})));
   const missing=[...new Set([...strings(snapshot.incident?.unknowns),...strings(latest.missing)])];
   section('不足している情報',missing.length?missing:['この欄に追加の不足情報は記録されていません。']);
   section('判断と調査の流れ',decisions.length?[]:['判断の記録はありません。'],decisions);
   section('根拠として使った情報',facts.length?[]:['この版には、取得した根拠の記録がありません。'],facts.map((f,i)=>({title:'根拠'+(i+1)+'：'+(({UNVERIFIED_REPORT:'利用者等からの報告（未検証）',REFERENCE:'資料の記述',OBSERVATION:'取得した観測記録'})[f.basis_type]||'取得した情報'),lines:[f.coverage?'確認範囲：'+f.coverage:'',f.acquisition_state==='ACCESS_DENIED'?'権限不足で取得できていません。':f.acquisition_state==='FAILED'?'取得に失敗しています。':f.acquisition_state==='NOT_OBSERVED'?'観測値を取得できていません。':'',...(f.field&&Object.prototype.hasOwnProperty.call(f.field,'value')?valueLines(f.field.value):['この項目の値は記録されていません。'])].filter(Boolean)})));
   section('実施した読み取り',array(data.actions).length?[]:['この版には、読み取り操作を実行した記録はありません。'],array(data.actions).map((a,i)=>({title:'読み取り'+(i+1),lines:[...valueLines(a.result_json?.state||a.state||'取得状態は原文を確認','取得状態'),...valueLines(a.result_json&&Object.prototype.hasOwnProperty.call(a.result_json,'values')?a.result_json.values:a.result_json&&Object.prototype.hasOwnProperty.call(a.result_json,'value')?a.result_json.value:a.result_json?.coverage??'取得結果の詳細は原文に記録されています。','取得結果')]})));
   section('修復候補と承認',array(snapshot.repair_candidates).length?['保存された候補です。修復の実行や正式承認を示すものではありません。']:['この版には、修復候補は登録されていません。'],array(snapshot.repair_candidates).map((c,i)=>{const p=c.proposal||{};return {title:'修復候補'+(i+1),lines:[p.reason,p.impact?'影響：'+p.impact:'',p.verification?'確認方法：'+p.verification:'',p.rollback?'切戻し：'+p.rollback:''].filter(Boolean)};}));
   return {title:'障害調査の報告',sections};
  }
  if(data.model_design){const d=data.model_design;
   section('設計の目的',[d.intent,d.current_state]);
   section('構成の提案',[],array(d.components).map(c=>({title:c.name,lines:[c.purpose,c.state==='PROPOSED'?'提案する構成です。':'既存と報告されていますが、実環境での確認はこれからです。']})));
   const names=new Map(array(d.components).map(c=>[c.id,c.name]));
   section('通信・接続の案',array(d.connections).length?[]:['この欄に接続の記録はありません。'],array(d.connections).map(c=>({title:(names.get(c.from)||'接続元は原文を確認')+' → '+(names.get(c.to)||'接続先は原文を確認'),lines:[c.purpose]})));
   section('採用した理由',[],array(d.decisions).map(c=>({title:c.proposal,lines:[c.reason]})));
   section('未確定の事項',array(d.unknowns).length?[]:['この欄には未確定事項が記録されていません。'],array(d.unknowns).map(c=>({title:c.description,lines:[c.resolution,c.blocks?'確認が必要な範囲：'+c.blocks:''].filter(Boolean)})));
   section('作業・確認・切戻しの案',[],array(d.steps).map(c=>({title:(phases[c.phase]||'手順')+'：'+c.action,lines:[c.requires?'前提：'+c.requires:'',c.responsible_role?'担当する役割：'+c.responsible_role:'',c.expected_evidence?'残す証拠：'+c.expected_evidence:''].filter(Boolean)})));
   if(strings(d.risks).length)section('確認すべきリスク',strings(d.risks));
   return {title:d.title||'設計案（未承認）',sections};
  }
  if(data.proposal&&data.proposal.design_markdown!==undefined){const d=data.proposal;
   section('設計の段階',[({DRAFT:'初案',CONDITIONAL_DRAFT:'条件付きの草案',FINAL_DRAFT:'最終草案'})[data.completion]||'未承認の設計案']);
   section('未確定の事項',[],array(d.unknowns).map(c=>({title:c.question,lines:[c.purpose?'必要な理由：'+c.purpose:'',c.needed_material?'必要な資料：'+c.needed_material:''].filter(Boolean)})));
   section('移行の案',strings(d.migration));section('確認する内容',strings(d.verification));section('切戻しの案',strings(d.rollback));
   return {title:d.title||'AWSの設計案',sections,designMarkdown:typeof d.design_markdown==='string'?d.design_markdown:''};
  }
  if(data.schema==='ila.eca.full-route-draft.v1'){
   const r=data.route_result||{},v=r.value??r.call?.value,route=data.route,failed=layers(r).some(x=>x.error_code||x.error_type);
   const state=present({operation:'run',state:'FINISHED',result_category:failed?'FAILED':r.status==='HOLD'?'WAITING_INFORMATION':'FINISHED',outcome:r.status||r.state||'RECORDED',result_summary:r},route);
   section('処理の結果',[state.result,state.reason]);
   if(route==='D'&&v&&typeof v==='object'){section('質問への回答',[v.answer]);section('根拠の引用',[],array(v.citations).map(c=>({title:'資料からの引用',quotes:[c.quote]})));section('確認できていないこと',strings(v.unknowns));}
   else if(route==='E'&&v&&typeof v==='object'){
    section('会議本文からの抽出',['以下は発言内容の記録です。作業の完了や正式承認を認定するものではありません。']);
    section('主張に関する発言',array(v.claims).length?[]:['この欄に抽出された発言はありません。'],array(v.claims).map(c=>({title:({WORK_COMPLETED:'作業の完了に関する発言',CONFIG_CHANGED:'設定の変更に関する発言'})[c.kind]||'会議での主張',lines:[({AFFIRMED:'本文で肯定した発言として抽出',DENIED:'本文で否定した発言として抽出'})[c.stance]||'発言の分類は原文に記録',({DIRECT:'本人確認を伴わない、本文中の直接の表現',HEARSAY:'伝聞としての表現',QUESTION:'質問としての表現',PROPOSAL:'提案としての表現'})[c.mode]||'発言の形式は原文を確認'],quotes:[c.quote]})));
    section('決定に関する発言',array(v.decisions).length?[]:['この欄に抽出された発言はありません。'],array(v.decisions).map(c=>({title:'決定に関する発言',quotes:[c.quote]})));
    section('依頼・作業に関する発言',array(v.actions).length?[]:['この欄に抽出された発言はありません。'],array(v.actions).map(c=>({title:'本文に記載された作業・依頼',quotes:[c.quote],lines:[c.assignee_quote?'担当者についての本文表現：'+c.assignee_quote:'',c.due_quote?'期限についての本文表現：'+c.due_quote:''].filter(Boolean)})));
   }else if(route==='H'&&v&&typeof v==='object'){
    section('判断の要旨',[v.summary]);section('検討した仮説',[],array(v.hypotheses).map(c=>({title:c.explanation,lines:['評価：'+hStatus(c.status),...strings(c.missing).map(x=>'不足している情報：'+x)]})));
    section('未承認の対策候補',[],array(v.recommendations).map(c=>({title:c.proposal,lines:[c.impact?'影響：'+c.impact:'',c.verification?'確認方法：'+c.verification:'',c.rollback?'切戻し：'+c.rollback:''].filter(Boolean)})));section('確認できていないこと',strings(v.unknowns));
   }else if(route==='B'&&r.plan){section('作業の順番（未実施）',strings(r.plan.order).map((x,i)=>(i+1)+'. '+x));section('計画についての記録',[r.plan.note]);}
   else if(typeof v==='string')section('保存された回答',[v]);
   section('次に必要な操作',[state.next]);return {title:({D:'資料への質問と回答',E:'会議内容の解析記録',F:'構成・状態の確認記録',H:'セキュリティ調査の記録',B:'作業計画の記録'})[route]||'処理結果の記録',sections};
  }
  section('保存された成果物について',['構造化された原本と文書を保存しています。対応する詳しい内容は、原文表示またはダウンロードで確認できます。']);return {title:'成果物の確認',sections};
 }

 return {present,explainReason,summaryText,creationLabel,documentLabel,documentProjection};
})();
/* RECORD_VIEW_END */

const $=(q)=>document.querySelector(q), app=$('#app');
let settings, current, currentView, detail, selectedDocument, busy=false, timer;
const documentChoices=new Map(), reviewChoices=new Map();
const esc=(s)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const labels={LIVE_COMPARISON_ASTRA_SYNTHETIC_ONLY:'Astra実接続の比較試験（合成資料）',LIVE_COMPARISON_ASTRA_AUTH_RECOVERY_SAME_CASE:'認証更新後のAstra比較試験',MOCK:'模擬接続 / 合成資料',NOT_CONFIGURED:'生成接続 未設定',LOCAL_MODEL:'ローカル実モデル',QUEUED:'実行待ち',RUNNING:'処理中',FINISHED:'処理結果を記録',FAILED:'処理失敗',HOLD:'情報不足・保留',RECEIVED:'受付済み',ACTIVE:'調査中',WAITING_INFORMATION:'追加情報待ち',AWAITING_REVIEW:'レビュー待ち',WAITING_REPAIR:'修復候補・承認待ち',CANCELED:'利用者による中断',STOP_REQUESTED:'中断要求を記録',RESULT_UNKNOWN:'結果不明・照合が必要',INPUT_SAVED:'依頼を保存',DONE:'解析結果を記録',ANALYSIS_FAILED:'前回の解析は未完了',ANALYZING:'解析中',READY:'取込み済み',SAVED_NOT_PROCESSED:'保存済み・取込み待ち',GENERATED:'生成を記録',SUBMITTED:'レビュー提出済み'};
function badge(x){return `<span class="badge ${['FAILED','RESULT_UNKNOWN'].includes(x)?'bad':['HOLD','WAITING_INFORMATION','AWAITING_REVIEW','NOT_CONFIGURED','STOP_REQUESTED'].includes(x)?'warn':['READY','GENERATED','SUBMITTED'].includes(x)?'good':''}">${esc(labels[x]||x)}</span>`;}
async function api(path,body){const r=await fetch('/api/'+path,{method:body?'POST':'GET',headers:{'X-ILA-UI':'same-origin',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});const v=await r.json();if(!r.ok)throw Error(v.error||'通信に失敗しました。結果を確認してから再開してください。');return v;}
function notice(text,error=false){$('#notice').className=error?'error':'success';$('#notice').textContent=text;}
function resetNotice(){$('#notice').className='';$('#notice').textContent='';}
async function guarded(fn){if(busy)return;busy=true;document.querySelectorAll('[data-write]').forEach(b=>b.disabled=true);try{await fn();}catch(e){notice(e.message+'（自動再送はしません）',true);}finally{busy=false;document.querySelectorAll('[data-write]').forEach(b=>b.disabled=false);}}
function safeURL(url){try{const u=new URL(url);return ['http:','https:'].includes(u.protocol)&&!u.username&&!u.password?u.href:null;}catch{return null;}}
function external(url,name){const v=safeURL(url);return v?`<a href="${esc(v)}" target="_blank" rel="noopener noreferrer">${esc(name)} ↗</a>`:'リンクなし';}
// Raw HTML is always escaped. Only explicit http(s) links are activated; no images.
function inline(s){return esc(s).replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>').replace(/\[([^\]]+)\]\(([^)]+)\)/g,(_,label,url)=>{const u=safeURL(url.replace(/&amp;/g,'&'));return u?`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${label}</a>`:label;});}
function markdown(text){let code=false,lines=[],block=[];for(const line of text.split(/\r?\n/)){if(line.startsWith('```')){if(code){lines.push('<pre><code>'+esc(block.join('\n'))+'</code></pre>');block=[];}code=!code;continue;}if(code){block.push(line);continue;}const h=line.match(/^(#{1,6})\s+(.*)$/);if(h)lines.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`);else if(/^[-*]\s/.test(line))lines.push('<p>• '+inline(line.slice(2))+'</p>');else if(line.startsWith('>'))lines.push('<blockquote>'+inline(line.slice(1))+'</blockquote>');else lines.push(line?'<p>'+inline(line)+'</p>':'');}if(code)lines.push('<pre>'+esc(block.join('\n'))+'</pre>');return lines.join('');}
function tabs(cid,view){return `<div class="tabs"><a class="${view==='detail'?'selected':''}" href="#detail/${cid}">案件詳細</a><a class="${view==='input'?'selected':''}" href="#input/${cid}">入力・実行</a></div>`;}
function heading(k,title,description,button=''){return `<div class="page-top"><div><div class="kicker">${k}</div><h1>${esc(title)}</h1><p class="muted">${esc(description)}</p></div>${button}</div>`;}
async function list(){const rows=await api('cases?q='+encodeURIComponent($('#search')?.value||''));if(currentView!=='cases')return;
 app.innerHTML=heading('CASE MANAGEMENT','案件一覧','依頼、証跡、成果物を一つの案件から確認できます。','<button class="primary" id="newCase">＋ 案件を登録</button>')+
 `<div class="stats">${[['全案件',rows.length],['処理中',rows.filter(r=>['ACTIVE','QUEUED','RUNNING'].includes(r.status)).length],['追加情報待ち',rows.filter(r=>['HOLD','WAITING_INFORMATION','RESULT_UNKNOWN'].includes(r.status)).length],['レビュー待ち',rows.filter(r=>['AWAITING_REVIEW','WAITING_REPAIR'].includes(r.status)).length]].map(([n,v])=>`<div class="stat"><span>${n}</span><strong>${v}</strong></div>`).join('')}</div>`+
 `<section class="panel"><div class="panel-top"><h2>登録済み案件 <span class="section-count">${rows.length}件</span></h2><input id="search" class="search" placeholder="案件名・依頼文で検索" aria-label="案件を検索"></div><table><thead><tr><th>案件 / 業務</th><th>状態</th><th>成果物</th><th>実行区分</th><th></th></tr></thead><tbody>${rows.map(r=>`<tr><td><span class="route-icon">${r.route}</span><a class="case-name" href="#detail/${r.case_id}">${esc(r.title)}</a><span class="function">${esc(settings.routes[r.route])}${r.notification?' · 通知から受付':''}</span></td><td>${badge(r.status)}</td><td>${r.documents}件</td><td>${badge(r.mode)}</td><td><a href="#input/${r.case_id}">開く →</a></td></tr>`).join('')}</tbody></table>${rows.length?'':'<div class="empty">案件はまだありません。最初の依頼を登録してください。</div>'}</section>`+
 `<div class="hint">進捗は保存された実行状態を表示します。情報不足・結果不明・利用者中断は、完了として扱いません。</div>`;
 $('#newCase').onclick=()=>location.hash='new';let t;$('#search').oninput=()=>{clearTimeout(t);const value=$('#search').value;t=setTimeout(async()=>{await listWithSearch(value);},350);};}
async function listWithSearch(value){const rows=await api('cases?q='+encodeURIComponent(value));if(currentView!=='cases')return;const tbody=$('tbody');tbody.replaceChildren();for(const r of rows){const tr=document.createElement('tr');tr.innerHTML=`<td><a class="case-name" href="#detail/${r.case_id}">${esc(r.title)}</a><span class="function">${esc(settings.routes[r.route])}</span></td><td>${badge(r.status)}</td><td>${r.documents}件</td><td>${badge(r.mode)}</td><td><a href="#input/${r.case_id}">開く →</a></td>`;tbody.append(tr);}}
function routeOptions(selected){return Object.entries(settings.routes).map(([k,v])=>`<option value="${k}" ${selected===k?'selected':''}>${esc(v)}</option>`).join('');}
function newForm(){app.innerHTML=heading('NEW CASE','案件を登録','業務と依頼を選んで受付します。登録だけではモデル呼出しや外部送信は行いません。')+`<section class="panel"><form id="register"><div class="two-col"><div><label>案件名<input id="title" required maxlength="250" placeholder="例：検証環境の接続構成を見直す"></label><label>業務<select id="route">${routeOptions('A')}</select></label><label>依頼内容<textarea id="text" placeholder="何を確認・作成したいか、普段の言葉で書いてください。資料や文字起こしは登録後に追加できます"></textarea></label><label>対象環境<textarea id="environment" placeholder="確認できた環境情報だけを記入してください"></textarea></label></div><div><div class="callout">資料は登録後に追加できます。案件、実行要求、原入力は既存の監査DBへ保存します。</div><p class="hint">設計はレビュー用の草案です。承認や構築は別の状態として管理します。</p></div></div><div class="sticky-actions"><button type="submit" class="primary" data-write>登録して入力へ</button><a href="#cases">キャンセル</a></div></form></section>`;
 $('#register').onsubmit=e=>{e.preventDefault();guarded(async()=>{const form={title:$('#title').value,route:$('#route').value,text:$('#text').value,environment:$('#environment').value,parameters:[],constraints:'',unknowns:''};const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(form)));const key=[...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,'0')).join('');const r=await api('cases',{form,request_key:key});location.hash='input/'+r.case_id;});};}
function parameterRow(v={name:'',value:'',type:'text',unit:''}){return `<div class="field-row"><input class="pname" aria-label="設定項目名" placeholder="項目名" value="${esc(v.name)}"><input class="pvalue" aria-label="設定値" placeholder="値" value="${esc(v.value)}"><select class="ptype" aria-label="値の型">${[['text','文字列'],['number','数値'],['boolean','真偽値']].map(([k,n])=>`<option value="${k}" ${v.type===k?'selected':''}>${n}</option>`).join('')}</select><input class="punit" aria-label="単位" placeholder="単位" value="${esc(v.unit)}"><button type="button" class="removeParam" aria-label="項目を削除">×</button></div>`;}
function collectForm(){const params=[...document.querySelectorAll('.field-row')].map(row=>{const t=row.querySelector('.ptype').value,raw=row.querySelector('.pvalue').value;let value=raw;if(t==='number'){if(!raw.trim()||!Number.isFinite(Number(raw)))throw Error('数値の項目には有効な数値を入力してください');value=Number(raw);}if(t==='boolean'){if(!['true','false'].includes(raw))throw Error('真偽値は true または false を指定してください');value=raw==='true';}return {name:row.querySelector('.pname').value,value,type:t,unit:row.querySelector('.punit').value};});
 return {title:detail.form.title,route:detail.form.route,text:$('#request').value,...(detail.form.route==='E'?{meeting_text:$('#meetingReceipt').value?'':$('#meetingText')?.value||'',meeting_receipt_key:$('#meetingReceipt').value}:{}),environment:$('#env').value,constraints:$('#constraints').value,unknowns:$('#unknowns').value,parameters:params,stage:$('#stage')?.value||'DRAFT',task_kind:$('#taskKind')?.value||'CHANGE',...($('#changeTarget')?{change_key:$('#changeTarget').value}:{}),expected_revision:Math.max(0,...detail.documents.filter(d=>d.design_id.startsWith('DESIGN-')).map(d=>d.revision)),resume_reason:$('#resumeReason')?.value||''};}

function transcriptHTML(text){const parts=RequestView.transcript(text);return parts.length?`<div class="meeting-reading">${parts.map(p=>`<div class="utterance">${p.time?`<span class="utterance-time">${esc(p.time)}</span>`:''}<div>${p.speaker?`<span class="hint">記録上の話者：${esc(p.speaker)}（本人未確認）</span>`:''}<p>${esc(p.text)}</p></div></div>`).join('')}</div>`:'<p class="hint">会議本文はまだ登録されていません。</p>';}
function meetingInputHTML(f){const selected=f.meeting_receipt_key||'',text=f.meeting_text||'',timed=RequestView.isTimed(text);return `<section class="meeting-input"><h3>解析する会議資料</h3><p class="hint">上の依頼内容と、解析する本文は別に保存します。資料を選ぶと本文の貼り直しは不要です。</p><label for="meetingReceipt">解析対象<select id="meetingReceipt"><option value="">会議本文を直接入力する</option>${detail.meeting_materials.map((m,i)=>`<option value="${esc(m.receipt_id)}" ${m.receipt_id===selected?'selected':''}>${m.kind==='TEXT'?'文字起こし':'録音'} ${i+1}（${m.intake_origin==='GOOGLE_API_READ'?'Googleから取得':'ファイル投入'}・版${esc(m.version)}）</option>`).join('')}</select></label><div id="meetingEditor" ${selected?'class="hidden"':''}><details id="timedMeetingEditor" ${timed?'':'open'}><summary>${timed?'保存済み本文の編集欄を開く':'会議本文を入力・編集'}</summary><label for="meetingText">会議本文・文字起こし<textarea id="meetingText" placeholder="例：担当者：設計案はレビュー中です。承認が済むまで変更しません。">${esc(text)}</textarea></label></details></div><div id="meetingReading">${transcriptHTML(selected?(detail.meeting_materials.find(m=>m.receipt_id===selected)?.text||''):text)}</div></section>`;}
function wireMeetingInput(){if(!$('#meetingReceipt'))return;function draw(){const key=$('#meetingReceipt').value;$('#meetingEditor').classList.toggle('hidden',!!key);$('#meetingReading').innerHTML=transcriptHTML(key?(detail.meeting_materials.find(m=>m.receipt_id===key)?.text||''):$('#meetingText').value);}$('#meetingReceipt').onchange=draw;$('#meetingText').oninput=draw;}
function artifactOptions(documents,preference){return documents.map((d,i)=>({d,i})).reverse().map(({d,i})=>`<option value="${d.key}" ${d.key===preference?'selected':''}>${esc(RequestView.artifactLabel(d,i))}</option>`).join('');}

async function loadDetail(cid){const loaded=await api('cases/'+cid);if(current===cid)detail=loaded;return loaded;}
function uploadPanel(){return `<section class="panel"><h2>入力資料</h2><p class="hint">UTF-8のTXT・Markdown・HTML・JSON、VTT・音声を保存します。資格情報は投入しないでください。資料の由来とハッシュを保持します。</p><label>資料の役割<select id="sourceKind"><option value="TECHNICAL_REFERENCE">技術資料・参考資料</option><option value="ENVIRONMENT">対象環境の情報</option><option value="REQUIREMENT">要件</option><option value="POLICY">方針・制約</option><option value="MEETING">会議の文字起こし・音声</option></select></label>${detail.meetings.length?`<label>関連する会議<select id="uploadMeeting"><option value="">関連付けなし</option>${detail.meetings.map(m=>`<option value="${esc(m.meeting_key)}">${esc(m.title||m.start)}</option>`).join('')}</select></label>`:''}<label>ファイル<input type="file" id="file" accept=".txt,.md,.html,.json,.vtt,.wav,.mp3,.mp4,.m4a,.ogg,.flac"></label><button id="upload" data-write>資料を保存・取り込む</button><div id="materialList">${materialsHTML()}</div></section>`;}
function materialsHTML(){return detail.materials.map(m=>`<div class="item">${badge(m.intake_state)}<strong>${esc(m.name)}</strong><small>${esc(m.kind)} · ${m.bytes.toLocaleString()} bytes</small><span class="hash">SHA-256 ${esc(m.sha256)}</span></div>`).join('')||'<p class="hint">登録された資料はありません。</p>';}
function inputView(){const f=detail.form,route=f.route;app.innerHTML=heading('INPUT & EXECUTION',f.title,settings.routes[route],badge(detail.mode))+tabs(current,'input')+
 `<div class="two-col"><div><section class="panel"><h2>依頼と対象環境</h2>${!settings.generation_enabled&&route!=='F'?'<div class="callout warn">生成接続が未設定です。入力と資料を保存し、実行結果は「接続未設定の保留」として記録します。外部APIへ切り替えません。</div>':''}<label for="request">依頼内容<textarea id="request" placeholder="何を確認・作成したいか、普段の言葉で記入してください">${esc(f.text||'')}</textarea></label>${route==='E'?'<p class="hint">例：会議で決まったことと、まだ承認されていない提案を整理してください。</p>':''}${detail.request_display_note?`<p class="hint">${esc(detail.request_display_note)}</p>`:''}${route==='E'?meetingInputHTML(f):''}<label>対象環境<textarea id="env">${esc(f.environment||'')}</textarea></label><details><summary>設定値を型と単位付きで登録</summary><p class="hint">入力した値だけを元資料として渡します。未観測の値や秘密値は入力しないでください。</p><div id="parameters">${(f.parameters||[]).map(parameterRow).join('')}</div><button id="addParam" type="button">＋ 設定項目</button></details><div class="row"><label>制約（1行1項目）<textarea id="constraints">${esc(f.constraints||'')}</textarea></label><label>不明なこと（1行1項目）<textarea id="unknowns">${esc(f.unknowns||'')}</textarea></label></div>
 ${route==='B'?`<label>作業計画の対象（許可済みの既存変更）<select id="changeTarget">${settings.changes.map(c=>`<option value="${esc(c.key)}">${esc(c.name)} · ${esc(c.status)}</option>`).join('')}</select></label><p class="hint">既存の承認済み変更だけを計画します。新しい実行権限は付与しません。</p>`:''}${route==='A'?`<label>設計の種類<select id="taskKind"><option value="CHANGE">既存環境の変更</option><option value="ADDITIONAL_BUILD" ${f.task_kind==='ADDITIONAL_BUILD'?'selected':''}>追加構築</option></select></label>`:''}
 ${route==='G'?`<label>作成する段階<select id="stage"><option value="DRAFT">初案・構成の検討</option><option value="FINALIZE" ${f.stage==='FINALIZE'?'selected':''}>追加資料を反映した最終草案（未承認）</option></select></label><p class="hint">同じ設計の版を追加します。最新の親版とハッシュはサーバーが照合します。実構築は行いません。</p>`:''}
 ${route==='C'?`<div class="callout">${detail.notifications?'監視通知から受け付けた障害案件です。':''}調査は登録済みの読み取り操作だけを使います。既存の仮説・証拠・上限を引き継ぎます。</div><label>再開・照合の理由<input id="resumeReason" placeholder="追加した資料や、再開する理由"></label>`:''}
 <div class="sticky-actions"><button id="saveRequest" data-write>依頼内容を保存</button><button class="primary" id="run" data-write>${detail.documents.length&&['A','G'].includes(route)?'追加情報を反映して改訂':'保存して実行'}</button>${route==='C'?'<button id="resume" data-write>保存状態から調査を再開</button><button id="reconcile" data-write>結果不明を照合</button>':''}</div><p class="hint">処理を受付後、この画面を閉じても記録は残ります。同じ入力は保存済みの実行へ戻ります。</p></section><section class="panel"><h2>実行状態</h2><div id="inputJobs">${jobsHTML()}</div></section></div><div>${uploadPanel()}${collaborationHTML()}</div></div>`;
 $('#addParam').onclick=()=>{$('#parameters').insertAdjacentHTML('beforeend',parameterRow());wireRemove();};wireRemove();if(['B','F'].includes(route)){for(const id of ['request','env','constraints','unknowns'])$('#'+id).readOnly=true;$('#parameters').parentElement.classList.add('hidden');}if(route==='E'){for(const id of ['env','constraints','unknowns'])$('#'+id).parentElement.classList.add('hidden');$('#parameters').parentElement.classList.add('hidden');}if(route==='E')$('#sourceKind').value='MEETING';$('#run').onclick=()=>runAction('run');if($('#resume'))$('#resume').onclick=()=>runAction('resume');if($('#reconcile'))$('#reconcile').onclick=()=>guarded(async()=>{await submitAction('reconcile',{reason:$('#resumeReason').value});});wireUpload();wireCollaboration();wireMeetingInput();$('#saveRequest').onclick=()=>runAction('save_request');}
function wireRemove(){document.querySelectorAll('.removeParam').forEach(b=>b.onclick=()=>b.parentElement.remove());}
function runAction(op){guarded(async()=>{await submitAction(op,collectForm());});}
async function submitAction(operation,payload){const action_key=crypto.randomUUID();const r=await api('cases/'+current+'/actions',{operation,payload,action_key});notice(r.duplicate?'同じ要求は受付済みです。保存された実行を表示します。':'要求を保存しました。実際に記録された状態を表示します。');await refresh();return r;}
function wireUpload(){$('#upload').onclick=()=>guarded(async()=>{const file=$('#file').files[0];if(!file)throw Error('ファイルを選んでください');if(file.size>settings.max_upload_bytes)throw Error('ファイルは設定された容量上限以内にしてください');const data=new Uint8Array(await file.arrayBuffer());let binary='';for(let i=0;i<data.length;i+=16384)binary+=String.fromCharCode(...data.subarray(i,i+16384));await api('cases/'+current+'/upload',{name:file.name,kind:$('#sourceKind').value,content_base64:btoa(binary),meeting_key:$('#uploadMeeting')?.value||null});notice('原資料を保存しました。取込み状態を確認してください。');await refresh();});}
function collaborationHTML(){return `<section class="panel" id="collaborationPanel"><h2>Google 会議・Drive</h2><p class="hint">Driveの取得は、Meetが録音・文字起こしを生成できたことを意味しません。取得できない資料はファイル投入を利用できます。</p>${settings.collaboration_configured?`<label>許可済みカレンダー<select id="calendar">${settings.calendars.map(c=>`<option value="${esc(c.key)}">${esc(c.name)}</option>`).join('')}</select></label><div class="row"><label>取得開始<input type="datetime-local" id="startDate"></label><label>取得終了<input type="datetime-local" id="endDate"></label></div><button id="syncGoogle" data-write>会議予定を取得・関連付け</button>`:'<div class="callout warn">接続設定が未登録です。アカウントや権限の設定は管理者がサーバー側で行います。</div>'}
 ${detail.meetings.map((m,i)=>`<div class="item"><strong>${esc(m.title||'関連会議 '+(i+1))}</strong><small>${esc(m.start)} ～ ${esc(m.end)}</small>${external(m.meet_url,'Google Meet')}<small>${esc(m.service_execution_kind)}</small><button data-collect="${esc(m.calendar_id+'|'+m.meeting_id)}" data-write>取得可能な会議資料を確認</button></div>`).join('')}
 ${settings.drive_files.length?`<label>許可済みDrive資料<select id="driveFile">${settings.drive_files.map(v=>`<option value="${esc(v.key)}">${esc(v.name)}</option>`).join('')}</select></label><button id="driveImport" data-write>Driveから取得</button>`:''}
 ${detail.meeting_materials.map((m,i)=>`<div class="item"><strong>${m.kind==='TEXT'?'文字起こし':'録音'} ${i+1}</strong><small>${m.intake_origin==='GOOGLE_API_READ'?'Googleから取得':'ファイルから取込み'} ／ ${esc(RequestView.mode(m.service_execution_kind))} ／ 資料の版 ${esc(m.version)}</small><details><summary>取得元・ハッシュを確認</summary><p class="hash">${esc(m.source)}<br>SHA-256 ${esc(m.sha256)}</p></details>${badge(m.display_state||m.state)}${m.kind==='TEXT'?`<details class="meeting-transcript"><summary>文字起こしを読む</summary>${transcriptHTML(m.text||'')}</details>`:''}<div class="links"><button data-original-meeting="${esc(m.receipt_id)}">取得した原文をダウンロード</button><button data-analyze="${esc(m.receipt_id)}" data-write>既存の会議解析へ渡す</button>${['ANALYZING','ANALYSIS_FAILED'].includes(m.state)?`<button data-resume-meeting="${esc(m.receipt_id)}" data-write>保存資料から解析を明示的に再開</button>`:''}</div></div>`).join('')}</section>`;}
function wireCollaboration(){if($('#syncGoogle'))$('#syncGoogle').onclick=()=>guarded(async()=>{if(!$('#startDate').value||!$('#endDate').value)throw Error('取得する日時の範囲を指定してください');await submitAction('google_sync',{calendar_key:$('#calendar').value,start:new Date($('#startDate').value).toISOString(),end:new Date($('#endDate').value).toISOString()});});
 if($('#driveImport'))$('#driveImport').onclick=()=>guarded(()=>submitAction('drive_import',{drive_key:$('#driveFile').value}));
 document.querySelectorAll('[data-collect]').forEach(b=>b.onclick=()=>guarded(async()=>{const m=detail.meetings.find(m=>m.calendar_id+'|'+m.meeting_id===b.dataset.collect);// Server-provided meeting binding; no typed internal identifier.
 const key=m.meeting_key;if(!key)throw Error('会議の関連付けを更新してから資料を取得してください');await submitAction('google_collect',{meeting_key:key});}));
 document.querySelectorAll('[data-resume-meeting]').forEach(b=>b.onclick=()=>guarded(()=>submitAction('meeting_analyze',{receipt_id:b.dataset.resumeMeeting,resume:true})));document.querySelectorAll('[data-original-meeting]').forEach(b=>b.onclick=()=>download('meeting',b.dataset.originalMeeting,''));document.querySelectorAll('[data-analyze]').forEach(b=>b.onclick=()=>guarded(()=>submitAction('meeting_analyze',{receipt_id:b.dataset.analyze})));}
function resultText(r){return RecordView.summaryText(r);}
function storyBadge(view){return `<span class="badge ${['FAILED','RESULT_UNKNOWN'].includes(view.status)?'bad':['CONTROL_STOP','WAITING_INFORMATION','WAITING_REPAIR','AWAITING_REVIEW'].includes(view.status)?'warn':''}">${esc(view.statusLabel)}</span>`;}
function jobsHTML(){return detail.jobs.slice().reverse().map(j=>{
 const view=RecordView.present(j,detail.form.route);
 return `<article class="item execution-record"><div class="record-head"><h3>${esc(view.title)}</h3>${storyBadge(view)}</div><p class="record-origin">${esc(view.modeLabel)}</p><dl class="record-story"><div><dt>結果</dt><dd>${esc(view.result)}</dd></div>${view.reason?`<div><dt>理由</dt><dd>${esc(view.reason)}</dd></div>`:''}${view.missing.length?`<div><dt>不足している情報</dt><dd><ul>${view.missing.map(s=>`<li>${esc(s)}</li>`).join('')}</ul></dd></div>`:''}<div><dt>次の操作</dt><dd>${esc(view.next)}</dd></div></dl>
 <details class="record-history"><summary>処理の流れを見る（${view.history.length}件）</summary><ol>${view.history.map(e=>`<li>${esc(e.label)}${e.note?`<p>${esc(e.note)}</p>`:''}</li>`).join('')}</ol>${view.history.length?'':'<p class="hint">受付後の実行記録は確認できていません。</p>'}</details>
 <details class="record-technical"><summary>診断用の記録（内部コード・原文）</summary><p class="hint">問い合わせや技術調査のための記録です。上の説明は表示用で、保存された判定や原応答を変更しません。</p><pre>${esc(JSON.stringify({record_reference:j.job_id,state:j.state,outcome:j.outcome,reason:j.reason,result_summary:j.result_summary,events:j.events},null,2))}</pre></details>
 ${j.state==='RESULT_UNKNOWN'?`<label>照合の理由<input class="job-reason" placeholder="中断状況と確認する理由"></label><button class="reconcile-job" data-job="${esc(j.job_id)}" data-write>保存済み結果を照合</button>`:''}${['QUEUED','RUNNING','STOP_REQUESTED'].includes(j.state)?`<button class="danger" data-stop="${esc(j.job_id)}" data-write>中断を要求</button><p class="hint">現在の呼出し結果を保存してから停止します。送信済み要求の取消しや未課金は保証しません。</p>`:''}</article>`;
 }).join('')||'<p class="hint">実行記録はありません。</p>';}
function wireStop(){document.querySelectorAll('.reconcile-job').forEach(b=>b.onclick=()=>guarded(()=>submitAction('reconcile',{job_id:b.dataset.job,reason:b.previousElementSibling.querySelector('input').value})));document.querySelectorAll('[data-stop]').forEach(b=>b.onclick=()=>guarded(async()=>{await api('cases/'+current+'/stop',{job_id:b.dataset.stop});notice('中断要求を記録しました。処理済みの結果と未完了を区別して保存します。');await refresh();}));}
function detailView(){const f=detail.form;app.innerHTML=heading('CASE DOSSIER',f.title,settings.routes[f.route],`<button class="primary" id="goInput">入力・実行へ →</button>`)+tabs(current,'detail')+
 `<div class="two-col"><div><section class="panel"><div class="panel-top"><h2>概要</h2>${badge(detail.mode)}</div><dl class="request-overview"><div><dt>依頼内容</dt><dd id="caseRequestText">${esc(f.text||'依頼内容は未登録です。入力・実行で記入してください。')}</dd></div><div><dt>対象環境</dt><dd>${esc(f.environment||'未記入')}</dd></div></dl>${detail.request_display_note?`<p class="hint">${esc(detail.request_display_note)}</p>`:''}<div class="row">${detail.jobs.length?storyBadge(RecordView.present(detail.jobs[detail.jobs.length-1],f.route)):badge('RECEIVED')}<span class="hint">正式承認と構築の実行許可は別々に確認します。</span></div>${detail.incident?`<div class="item"><strong>障害調査</strong> ${badge(detail.incident.status)}<p class="hint">${esc(RecordView.explainReason(detail.incident.reason))} · 調査 ${detail.incident.steps_used}/${detail.incident.max_steps} · 判断 ${detail.incident.calls_used}/${detail.incident.max_calls}</p></div>`:''}</section>
 <section class="panel"><h2>成果物・改訂履歴</h2>${detail.documents.length?`<div class="document-toolbar"><select id="versions" aria-label="表示する成果物の版">${artifactOptions(detail.documents,documentChoices.get(current))}</select><button id="downloadMd">Markdown</button><button id="downloadJson">JSON</button><button id="downloadIac">IaC</button></div><p class="hash" id="artifactHash"></p><div id="preview" class="preview">原文とハッシュを照合しています…</div><div id="citations"></div>`:'<div class="empty">成果物はまだありません。入力・実行から処理を開始できます。</div>'}</section><section class="panel"><h2>実行・調査の記録</h2><div class="timeline">${jobsHTML()}</div></section></div>
 <div><section class="panel"><h2>入力資料・根拠</h2><div id="sources"><p class="hint">資料を照合しています…</p></div><a href="#input/${current}">＋ 追加資料を取り込む</a></section><section class="panel"><h2>GitLab レビュー</h2><p class="hint">MR、コメント、CI成功、マージは正式承認と同一視しません。既存の承認条件と対象版・ハッシュ・コミットで照合します。</p>
 ${detail.documents.filter(d=>!d.native_lifecycle).length?`<label>提出する成果物<select id="reviewDocument">${artifactOptions(detail.documents.filter(d=>!d.native_lifecycle),reviewChoices.get(current))}</select></label><div class="links"><button id="prepareReview" data-write>送信対象を準備</button><button id="submitReview" data-write>許可済み資料をDraft MRへ提出</button></div>`:'<p class="hint">先に成果物を作成してください。</p>'}
 ${detail.links.map(l=>`<div class="item"><strong>提出 第${l.revision}版</strong> ${badge(l.state)}<p>${external(l.mr_url,'レビュー用MRを開く')}</p><small class="hash">成果物 ${esc(l.artifact_sha256)}<br>コミット ${esc(l.commit_sha||'未確定')}</small><p class="hint">レビュー：${esc(l.review.gitlab_approval_verified?'取得したレビュー情報あり':'未確認／無料レビュー専用')}<br>正式承認：${l.formal_approval==='INVALIDATED_NEWER_REVISION'?'改訂済みのため以前の承認は無効':'その都度、対象版と本人・権限の再照合が必要'}</p>${l.last_formal_check?`<div class="callout"><strong>保存された承認照合</strong><p>${esc(l.last_formal_check.recorded_at)}</p><p>${esc(resultText(l.last_formal_check.result||{}))||esc(RecordView.explainReason(l.last_formal_check.reason||l.last_formal_check.state))}</p><small>これは保存済みの照合時点の記録です。実行前には既存経路で再確認します。</small></div>`:''}<div class="links"><button data-refresh="${l.submission_key}" data-write>レビュー状態を取得</button><button data-formal="${l.submission_key}" data-write>正式承認を照合</button><button data-reconcile="${l.submission_key}" data-write>結果不明の提出を照合</button></div>${settings.reviewers.length?`<label>承認権限のある担当者<select class="reviewer">${settings.reviewers.map(v=>`<option value="${esc(v.key)}">${esc(v.name)}</option>`).join('')}</select></label><button data-assign="${l.submission_key}" data-write>既存の承認経路へ回付</button>`:''}</div>`).join('')||'<p class="hint">提出記録はありません。</p>'}<p class="hint">画面には承認を代行するボタンを設けていません。マージ・CI・構築は実行しません。</p></section>${collaborationHTML()}</div></div>`;
 $('#goInput').onclick=()=>location.hash='input/'+current;wireStop();wireCollaboration();wireReview();loadSources();
 if($('#versions')){$('#versions').onchange=()=>{documentChoices.set(current,$('#versions').value);loadDocument();};selectedDocument=detail.documents.find(d=>d.key===$('#versions').value);loadDocument();$('#downloadMd').onclick=()=>download('document',$('#versions').value,'md');$('#downloadJson').onclick=()=>download('document',$('#versions').value,'json');$('#downloadIac').onclick=()=>download('document',$('#versions').value,'iac');}}
function wireReview(){if($('#reviewDocument'))$('#reviewDocument').onchange=()=>reviewChoices.set(current,$('#reviewDocument').value);for(const [id,op]of [['prepareReview','gitlab_prepare'],['submitReview','gitlab_submit']]){if($('#'+id))$('#'+id).onclick=()=>guarded(()=>submitAction(op,{document_key:$('#reviewDocument').value}));}
 for(const [selector,op]of [['refresh','gitlab_refresh'],['formal','formal_status'],['reconcile','gitlab_reconcile']])document.querySelectorAll('[data-'+selector+']').forEach(b=>b.onclick=()=>guarded(()=>submitAction(op,{submission_id:b.dataset[selector]})));
 document.querySelectorAll('[data-assign]').forEach(b=>b.onclick=()=>guarded(()=>submitAction('formal_prepare',{submission_id:b.dataset.assign,reviewer_key:b.previousElementSibling.querySelector('select').value})));}
async function download(kind,key,format){try{const r=await fetch('/api/cases/'+current+'/download?kind='+kind+'&key='+encodeURIComponent(key)+'&format='+format,{headers:{'X-ILA-UI':'same-origin'}});if(!r.ok){const e=await r.json();throw Error(e.error);}const b=await r.blob(),url=URL.createObjectURL(b),a=document.createElement('a');a.href=url;a.download=(kind==='document'?'成果物-'+format:key)+'.'+(format==='iac'?'tf.json':format||'txt');a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){notice(e.message,true);}}
function readableDocumentHTML(projection){
 return `<div class="document-reading"><p class="hint">保存された構造化結果を、人が確認するために整理した表示です。原文は下の「保存された原文」を開くと確認できます。</p><h2>${esc(projection.title)}</h2>${projection.designMarkdown?markdown(projection.designMarkdown):''}${projection.sections.map(s=>`<section class="readable-section"><h3>${esc(s.heading)}</h3>${s.paragraphs.map(p=>`<p>${esc(p)}</p>`).join('')}${!s.paragraphs.length&&!s.entries.length?'<p class="hint">この欄に記録された項目はありません。</p>':''}${s.entries.map(e=>`<div class="readable-entry"><h4>${esc(e.title)}</h4>${(e.lines||[]).filter(x=>typeof x==='string'&&x).map(p=>`<p>${esc(p)}</p>`).join('')}${(e.quotes||[]).filter(x=>typeof x==='string').map(q=>`<blockquote>${esc(q)}</blockquote>`).join('')}</div>`).join('')}</section>`).join('')}</div>`;
}
async function loadDocument(){
 const key=$('#versions').value,cid=current;selectedDocument=detail.documents.find(d=>d.key===key);
 $('#artifactHash').textContent='選択した版を照合中…';$('#preview').textContent='選択した版の原文とハッシュを照合しています…';$('#citations').replaceChildren();
 try{
  const d=await api('cases/'+cid+'/document-view?key='+key);
  const response=await fetch('/api/cases/'+cid+'/download?kind=document&key='+encodeURIComponent(key)+'&format=json',{headers:{'X-ILA-UI':'same-origin'}});
  let projection;
  if(response.ok)projection=RecordView.documentProjection(await response.json());
  else projection={title:'保存された成果物',sections:[{heading:'内容の確認',paragraphs:['人向けの整理に使う構造化資料を取得できませんでした。保存された原文とダウンロードから内容を確認してください。'],entries:[]}]};
  if(cid!==current||$('#versions')?.value!==key)return;
  $('#artifactHash').textContent='保存済み成果物 ／ '+RecordView.creationLabel(d.creation_setting)+' ／ SHA-256 '+d.artifact_sha256;
  $('#preview').innerHTML=readableDocumentHTML(projection)+`<details class="original-document"><summary>保存された原文を表示（内部項目・JSON・詳細な根拠を含む）</summary><div class="original-document-body">${markdown(d.markdown)}</div></details>`;
  $('#citations').innerHTML=d.citations.length?'<h3>判断の引用から原資料へ</h3>'+d.citations.map((c,i)=>`<p><button class="citation-jump" data-index="${i}">${esc(c.title)} の該当箇所 →</button><small>「${esc(c.quote.slice(0,150))}」</small></p>`).join(''):'<p class="hint">引用との対応が記録されている場合は、ここから該当する原資料へ移動できます。対象版と該当箇所は右側の資料でも確認できます。</p>';
  document.querySelectorAll('.citation-jump').forEach(b=>b.onclick=()=>{const c=d.citations[Number(b.dataset.index)],source=$('#source-'+c.material_key);if(!source)return;source.open=true;const pre=source.querySelector('pre'),text=pre.textContent,start=text.indexOf(c.quote);if(start>=0)pre.innerHTML=esc(text.slice(0,start))+'<mark>'+esc(c.quote)+'</mark>'+esc(text.slice(start+c.quote.length));source.scrollIntoView({behavior:'smooth',block:'center'});});
 }catch(e){if(cid===current&&$('#preview'))$('#preview').textContent='表示の確認で停止しました。ページを更新して保存状態を確認してください。';}
}
async function loadSources(){try{const rows=await api('cases/'+current+'/sources');if(!$('#sources'))return;$('#sources').innerHTML=rows.map(s=>`<details class="item" id="source-${s.key}"><summary>${esc(s.title)}</summary><p class="hash">資料版 ${esc(s.version)}<br>SHA-256 ${esc(s.sha256)}</p><p class="hint">${esc(s.kind)} · 原資料。現在の実機状態の証明ではありません。</p><pre class="source-text">${esc(s.text)}</pre><button data-download-source="${s.key}">原資料をダウンロード</button></details>`).join('')||'<p class="hint">案件に登録された入力資料はありません。</p>';document.querySelectorAll('[data-download-source]').forEach(b=>b.onclick=()=>download('material',b.dataset.downloadSource,''));}catch(e){if($('#sources'))$('#sources').textContent=e.message;}}
async function refresh(){if(!current)return;const cid=current,old=detail;await loadDetail(cid);if(cid!==current)return;if(currentView==='input'){if($('#collaborationPanel')&&(JSON.stringify(detail.meetings)!==JSON.stringify(old.meetings)||JSON.stringify(detail.meeting_materials)!==JSON.stringify(old.meeting_materials))){$('#collaborationPanel').outerHTML=collaborationHTML();wireCollaboration();}if($('#materialList'))$('#materialList').innerHTML=materialsHTML();if($('#inputJobs')){$('#inputJobs').innerHTML=jobsHTML();wireStop();}}else if(currentView==='detail'){const changed=JSON.stringify(detail.jobs)!==JSON.stringify(old.jobs)||detail.documents.length!==old.documents.length||JSON.stringify(detail.links)!==JSON.stringify(old.links)||JSON.stringify(detail.meetings)!==JSON.stringify(old.meetings)||JSON.stringify(detail.meeting_materials)!==JSON.stringify(old.meeting_materials);if(changed)detailView();}}
let navigationEpoch=0;async function navigate(){const epoch=++navigationEpoch;clearInterval(timer);resetNotice();app.innerHTML='<div class="panel" aria-busy="true">保存された案件情報を読み込んでいます…</div>'; const parts=location.hash.slice(1).split('/');currentView=parts[0]||'cases';current=parts[1];$('#nav-cases').classList.toggle('active',currentView!=='new');$('#nav-new').classList.toggle('active',currentView==='new');$('#breadcrumb').textContent=({cases:'案件一覧',new:'案件を登録',input:'入力・実行',detail:'案件詳細'})[currentView]||'案件一覧';try{if(currentView==='new')newForm();else if(['input','detail'].includes(currentView)&&current){await loadDetail(current);if(epoch!==navigationEpoch)return;currentView==='input'?inputView():detailView();timer=setInterval(()=>refresh().catch(e=>notice(e.message,true)),1800);}else{currentView='cases';current=null;await list();}}catch(e){notice(e.message,true);}}
window.addEventListener('hashchange',navigate);
api('settings').then(v=>{settings=v;$('#mode').textContent=labels[v.mode]||v.mode;navigate();}).catch(e=>notice('接続できません：'+e.message,true));
