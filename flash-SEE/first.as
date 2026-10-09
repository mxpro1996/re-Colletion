import flash.filesystem.*;
import flash.data.*;


// for sel Input database
var db:File = File.documentsDirectory;
function FileSelected_Callback(event:Event):void
{
	Label_1.text=db.nativePath;
}

var clickSelIn:Function=function(){
	function selectDataFile(root:File):void
	{
 		var dbFilter:FileFilter = new FileFilter("SQL Database", "*.db;*.dat");
 		root.browseForOpen("SQL Database Choose", [dbFilter]);
    	root.addEventListener(Event.SELECT, FileSelected_Callback);
	}
	selectDataFile(db);
}
But_SelIn.addEventListener("click",clickSelIn);



// for sel OutPut Path
var out_path:File = File.documentsDirectory;
function PathSelected_Callback(event:Event):void
{
	Label_2.text=out_path.nativePath;
}

var clickSelOut:Function=function(){
 	out_path.browseForDirectory("Output Directory");
    out_path.addEventListener(Event.SELECT, PathSelected_Callback);
}
But_SelOut.addEventListener("click",clickSelOut);



var tableName:String;
const dbKey:ByteArray = new ByteArray();
tableName = "scenariotbl"; // DB name, TBD
dbKey.writeUTFBytes("Egroj38D9fUNkkgB"); // DB Key
function Connect_Database(conn:SQLConnection):void
{
	try { 
          conn.open(db, SQLMode.UPDATE, false, 1024, dbKey); 
          trace("the database was created successfully"); 
    } catch (error:SQLError) { 
      	if (error.errorID == 3138) { 
      	  trace("Incorrect encryption key"); 
     	 } else{ 
     	    trace("Error message:", error.message); 
     	    trace("Details:", error.details); 
    	 } 
    }
}

function SQL_Execute(conn:SQLConnection, sqlStr:String):SQLResult
{
    var sqlRes:SQLResult = null;
    var sqlStatement:SQLStatement = new SQLStatement();
    sqlStatement.sqlConnection = conn;
    try{
       sqlStatement.text = sqlStr;
       sqlStatement.execute();
       sqlRes = sqlStatement.getResult();
	   return sqlRes;
    }catch(e:*){
       trace("SQL Command execute error");
    }
	return null;
}



// for extractor
var clickExtract:Function=function(){
	Fin_01.text="";
	if(Label_1.text!="" && Label_2.text!=""){
		 trace("Start the extractor process");
		 var conn:SQLConnection = new SQLConnection();
		 Connect_Database(conn);
		 var sqlRes:SQLResult = SQL_Execute(conn,"SELECT * from "+tableName);
		 
         var texts:Vector.<*> = Vector.<*>(sqlRes.data);
         for (var i:int = 0; i < texts.length; i++) { 
            var file:File = out_path.resolvePath(texts[i].id+".xml");
            var fileStream:FileStream = new FileStream(); 
            fileStream.open(file, FileMode.WRITE);
            fileStream.writeUTFBytes(texts[i].data);
            trace("Output to "+texts[i].id+".xml");
            fileStream.close();
         }
         trace("All is well, application is shutting down.")
		 Fin_01.text="Unpack finished;
	}else{
		trace("Missing parameters");
	}
}
But_Extract.addEventListener("click",clickExtract);




// for editor
var rival:File = File.documentsDirectory;
function RivalSelected_Callback(event:Event):void
{
	Label_3.text=rival.nativePath;
}

var clickSelNew:Function=function(){
	function selectDataFile(root:File):void
	{
 		var dbFilter:FileFilter = new FileFilter("XML Document", "*.xml");
 		root.browseForOpen("XML Text Insert", [dbFilter]);
    	root.addEventListener(Event.SELECT, RivalSelected_Callback);
	}
	selectDataFile(rival);
}
But_SelNew.addEventListener("click",clickSelNew);

var clickApply:Function=function(){
	Fin_02.text="";
	if(Label_1.text!="" && Label_3.text!=""){
		 trace("Start the replacer process");
		 var xml_id:String = rival.name.split(".")[0];
		 // trace(xml_id);
		 var conn:SQLConnection = new SQLConnection();
		 Connect_Database(conn);
		 
		 var sqlRes:SQLResult = null;
    	 var sqlStatement:SQLStatement = new SQLStatement();
		 var sqlStr:String = null;
		 sqlStatement.sqlConnection = conn;
		 sqlStr = "UPDATE " + tableName+" SET data=:data WHERE id=:id";
		 sqlStatement.text = sqlStr;
         sqlStatement.parameters[":id"] = xml_id; // the xml name
		 
		 var XMLContent:ByteArray = new ByteArray();
		 var fileStream:FileStream = new FileStream(); 
         fileStream.open(rival, FileMode.READ);
		 XMLContent = fileStream.readUTFBytes(rival.size);
         fileStream.close();
		 sqlStatement.parameters[":data"] = XMLContent; // the byteArray for fileContent
		 
		 try{
      		 sqlStatement.execute();
      		 sqlRes = sqlStatement.getResult();
			 conn.close();
   		 }catch(e:*){
    		   trace("SQL Command execute error");
   		 }
		 
		 trace("All is well, application is shutting down.")
		 Fin_02.text="Replace Finished";
	}else{
		trace("Missing parameters");
	}
}
But_Apply.addEventListener("click",clickApply);
