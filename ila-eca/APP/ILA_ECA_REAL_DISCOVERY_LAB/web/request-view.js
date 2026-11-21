'use strict';
// Read-only presentation. Text sent to the existing analysis is never replaced.
const RequestView=(()=>{
 function transcript(source){
  const lines=String(source||'').replace(/^\uFEFF/,'').split(/\r?\n/),items=[];
  const timed=lines[0]?.startsWith('WEBVTT')||lines.some(x=>/^\d{2}:\d{2}(?::\d{2})?[.,]\d{3}\s+-->/.test(x));
  if(!timed)return lines.filter(x=>x.trim()).map(text=>({text,time:'',speaker:''}));
  let time='',speaker='',parts=[];
  function emit(){if(parts.length)items.push({text:parts.join('\n'),time,speaker});parts=[];speaker='';}
  for(const line of lines){
   if(line.startsWith('WEBVTT')||/^\s*\d+\s*$/.test(line))continue;
   if(/^\d{2}:\d{2}(?::\d{2})?[.,]\d{3}\s+-->/.test(line)){emit();time=line.split(/\s+-->/)[0];continue;}
   if(!line.trim()){emit();continue;}
   const voice=line.match(/^<v(?:\.[^\s>]*)?\s+([^>]+)>([\s\S]*?)(?:<\/v>)?$/);
   if(voice){speaker=voice[1];parts.push(voice[2].replace(/<\/v>$/,''));}else parts.push(line);
  }
  emit();return items;
 }
 function isTimed(source){return /^\uFEFF?WEBVTT/.test(String(source||''))||/\d{2}:\d{2}(?::\d{2})?[.,]\d{3}\s+-->/.test(String(source||''));}
 function artifactLabel(doc,index){
  const kind=doc.result_status==='GENERATED'?'生成結果':doc.result_status==='HOLD'?'停止・保留の記録':doc.result_status==='AWAITING_REVIEW'?'レビュー用の草案':'成果物';
  return kind+' · 記録'+(index+1)+'・第'+doc.revision+'版';
 }
 function mode(mode){return ({LIVE_COMPARISON_ASTRA_SYNTHETIC_ONLY:'Astra実接続の比較試験（合成資料）',LIVE_COMPARISON_ASTRA_AUTH_RECOVERY_SAME_CASE:'認証更新後のAstra比較試験',LIVE:'実サービスから取得',MOCK:'模擬接続',REPLAY:'保存済み記録の再生',LOCAL_FILE:'手元のファイル'})[mode]||mode;}
 return {transcript,isTimed,artifactLabel,mode};
})();
if(typeof module!=='undefined')module.exports=RequestView;
