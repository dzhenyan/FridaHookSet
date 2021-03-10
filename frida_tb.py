import frida
import sys

module_script = """

Java.perform(function () {

    // 获取该应用加载的类
    var classNames = Java.enumerateLoadedClassesSync();
    
    for (var i = 0; i < classNames.length; i ++){
    
        send('class name: ' + classNames[i]);
        
    }
    var SwitchConfig = Java.use('mtopsdk.mtop.global.SwitchConfig');

    SwitchConfig.isGlobalSpdySwitchOpen.overload().implementation = function(){

        var ret = this.isGlobalSpdySwitchOpen.apply(this, arguments);

        send("isGlobalSpdySwitchOpenl " + ret);

        return false;

    }
    var SDKConfig = Java.use("mtopsdk.mtop.global.SDKConfig");

    SDKConfig.getGlobalAppVersion.overload().implementation = function(){
    
        var ret = this.getGlobalAppVersion.apply(this, arguments);
        
        send("getGlobalAppVersion " + ret);
        
        ret = "9.1.0";
        
        send("getGlobalAppVersion later"+ret);
        
        return ret
    }
    
    SDKConfig.getGlobalDeviceId.overload().implementation = function(){
    
        var ret = this.getGlobalDeviceId.apply(this, arguments);
        
        send("getGlobalDeviceId "+ret);
    }

    var TaobaoApplication = Java.use("com.taobao.tao.TaobaoApplication");

    TaobaoApplication.getAppVersion.overload().implementation = function(){
    
        var ret = this.getAppVersion.apply(this, arguments);
        
        send("getAppVersion "+ret);
        
        ret = "9.1.0";
        
        send("getAppVersion later "+ret);
        
        return ret;
    }

})

"""


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


# 1、Hook已启动起来的包的方式
# process = frida.get_remote_device().attach('com.yaotong.crackme')
# script = process.create_script(module_script)
# script.on('message', on_message)
# print('[*] Running CTF')
# script.load()
# sys.stdin.read()

# # 2、Hook启动界面的onCreate方式
device = frida.get_remote_device()
pid = device.spawn(['com.taobao.taobao'])
process = device.attach(pid)
script = process.create_script(module_script)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
device.resume(pid)
sys.stdin.read()
