import frida, sys

module_script = """

Java.perform(function () {

    send(Java.androidVersion); 
    
    send(Java.isMainThread());
    
    var SwanAppSearchFlowUBC = Java.use("com.baidu.swan.apps.statistic.search.SwanAppSearchFlowUBC");
    
    SwanAppSearchFlowUBC.handleExtra.overload("android.os.Bundle", "java.lang.String").implementation = function (s, b) {
    
        send("original call : str:" + b);
        
    }
    
    var SearchRecommendOthers = Java.use("com.xingin.alioth.entities.SearchRecommendOthers");
    
    SearchRecommendOthers.getSearchId.overload().implementation = function () {
    
        var search_id = this.getSearchId.apply(this, arguments);
        
        send("search_id:" + search_id);
        
    }
    
    var TaobaoApplication = Java.use("com.xingin.alioth.entities.SearchRecommendOthers");

    TaobaoApplication.getSearchId.overload().implementation = function(){
    
        var ret = this.getSearchId.apply(this, arguments);
        
        send("getSearchId "+ret);
        
        ret = "9.1.0";
        
        send("getSearchId later "+ret);
        
        return ret
    }
    
    var ResultNoteParser = Java.use("com.xingin.alioth.result.viewmodel.helper.ResultNoteParser");
    
    ResultNoteParser.implementation = function()
    {
        var arg0 = arguments[0];
        
        var arg1 = arguments[1];
        
        send("arg1 later " + arg1);
        
        send("params1: "+ arg0 +" params2: " + arg1);
        
        return this.formInclass(1,"Frida");
        
    }
    var SwanAppSearchFlowUBC = Java.use("com.baidu.swan.apps.statistic.search.SwanAppSearchFlowUBC");
    
    send(SwanAppSearchFlowUBC);
    
    SwanAppSearchFlowUBC.handleExtra.overload("android.os.Bundle", "java.lang.String").implementation = function(bundle, str){
    
        send("bundle : " + bundle);
        
        send("str : " + str);
        
    }
    
    var SearchView = Java.use("androidx.appcompat.widget.SearchView");
    
    send(SearchView);
    
    SearchView.getQuery.overload().implementation = function(){
    
        var text = this.getQuery.apply(this, arguments);
        
        send("text : " + text);
        
    }
    
    var SlideHelper = Java.use("com.baidu.searchbox.widget.SlideHelper");
    
    send(SlideHelper);
    
    SlideHelper.attachSlideView.overload('android.content.Context', 'android.view.View').implementation = function(context, view){
    
        send("c : " + context);
        
    }
    
    var NoteCollectedBoardsActivity = Java.use("com.xingin.xhs.ui.note.NoteCollectedBoardsActivity");
    
    send(NoteCollectedBoardsActivity);
    
    NoteCollectedBoardsActivity.getPageId.overload().implementation = function(){
    
        var ret = this.getPageId.apply(this, arguments);
        
        send("getCount "+ret);
    }
    
    var NoteAdView = Java.use("com.xingin.advert.search.note.NoteAdView");
    
    send(NoteAdView);
    
    NoteAdView.a.overload("java.lang.String","java.lang.String","int" ).implementation = function(str, str2, i2){
    
        send("invoke "+str);
        
    }
    
    var NoteAdView = Java.use("com.xingin.advert.search.note.NoteAdView"); 
    
    send(NoteAdView); 
    
    NoteAdView.a.overload(
    "java.lang.String", "java.lang.String","int").implementation = function(str, str2, i2){ 

        send("a 返回值为： "+ str); 
    } 
    
}) 
"""


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


# 1、Hook已启动起来的包的方式
process = frida.get_remote_device().attach('com.yaotong.crackme')
script = process.create_script(module_script)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
sys.stdin.read()

# # 2、Hook启动界面的onCreate方式
# device = frida.get_usb_device()
# pid = device.spawn(['com.yaotong.crackme'])
# process = device.attach(pid)
# script = process.create_script(module_script)
# script.on('message', on_message)
# print('[*] Running CTF')
# script.load()
# device.resume(pid)
# sys.stdin.read()
