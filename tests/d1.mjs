import {DatabaseSync} from 'node:sqlite';
export class D1 {
 constructor(){this.sqlite=new DatabaseSync(':memory:');}
 prepare(sql){return new Statement(this,sql);}
 async batch(statements){
  this.sqlite.exec('BEGIN');
  try{const results=statements.map(s=>s.execute());this.sqlite.exec('COMMIT');return results;}
  catch(e){this.sqlite.exec('ROLLBACK');throw e;}
 }
 close(){this.sqlite.close();}
}
class Statement {
 constructor(db,sql,args=[]){this.db=db;this.sql=sql;this.args=args;}
 bind(...args){return new Statement(this.db,this.sql,args.map(v=>v===undefined?null:v));}
 execute(){
  const stmt=this.db.sqlite.prepare(this.sql);let results=[];
  if(stmt.columns().length)results=stmt.all(...this.args);
  else stmt.run(...this.args);
  const changes=Number(this.db.sqlite.prepare('SELECT changes() AS n').get().n);
  return {success:true,results,meta:{changes,rows_read:results.length,rows_written:changes}};
 }
 async run(){return this.execute();}
 async all(){return this.execute();}
 async first(column){const row=this.execute().results[0]??null;return column?row?.[column]??null:row;}
}
