import frida
import sys

module_script = """

Java.perform(function () {

    send(Java.androidVersion);
    
    send(Java.isMainThread());
    
    // 获取该应用加载的类
    var classNames = Java.enumerateLoadedClassesSync();

    //for (var i = 0; i < classNames.length; i ++){
    
    //    send('class name: ' + classNames[i]);
    
    //}
    
    var SwanAppSearchFlowUBC = Java.use("com.ss.android.ugc.aweme.discover.commodity.c");
    
    SwanAppSearchFlowUBC.a.overload('java.lang.String', 'int', 'int', 'java.lang.String', 
    'java.lang.String').implementation = function (str, i, i2, str2, str3) { 
    
       send('/search/aggregate/shopping query : ' + str);
       
       send('/search/aggregate/shopping cursor  : ' + i.toString());
       
       send('/search/aggregate/shopping count  : ' + i2.toString());
       
       send('/search/aggregate/shopping search_source  : ' + str2);
       
       send('/search/aggregate/shopping enter_from  : ' + str3);
       
       this.a(str, i, i2, str2, str3);
       
    }
    
    var TC21MainInterface = Java.use("com.ss.android.ugc.tc.api.TC21MainInterface");
    
    TC21MainInterface.getRealCurrentTimeMilliseconds.implementation = function(){
    
        var ret = this.getRealCurrentTimeMilliseconds.apply(this, arguments);
        
        console.log("getRealCurrentTimeMilliseconds "+ret);
    }
    
    var TCInterceptor = Java.use("com.ss.android.ugc.tc.api.net.TCInterceptor");
    
    TCInterceptor.requestIntercept.implementation = function(request){
    
        send('into requestIntercept');
        
        var ret = this.requestIntercept(request);
        
        send ('ori : ' + ret);
        
        return ret;
        
    }
    
    var TokenD = Java.use("com.ss.android.token.d");
    
    TokenD.b.overload('java.lang.String').implementation = function(str){
    
        send('into TokenD.d');
        
        var ret = this.b(str);
        
        send ('X-Tt-Token : ' + ret);
        
        return ret;
        
    }
})
"""
on_create_script = """

//打印调用堆栈
function printStack(){

    send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    
}

Java.perform(function () {

    send(Java.androidVersion);
    
    send(Java.isMainThread());
    
    
    var TokenD = Java.use("com.ss.android.token.d");
    
    TokenD.b.overload('java.lang.String').implementation = function(str){
    
        send('into TokenD.d');
        
        var ret = this.b(str);
        
        printStack();
        
        send ('X-Tt-Token : ' + ret);
        
        return ret;
        
    }
})
"""


def on_message(message, data):
    if message['type'] == 'send':

        print("[*] {0}".format(message['payload']))

    else:

        print(message)


# # 1、Hook已启动起来的包的方式
# process = frida.get_remote_device().attach('com.ss.android.ugc.aweme')
# script = process.create_script(module_script)
# script.on('message', on_message)
# print('[*] Running CTF')
# script.load()
# sys.stdin.read()

# 2、Hook启动界面的onCreate方式
device = frida.get_remote_device()
pid = device.spawn(['com.ss.android.ugc.aweme'])
process = device.attach(pid)
script = process.create_script(on_create_script)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
device.resume(pid)
sys.stdin.read()
