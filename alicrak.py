import frida
import sys

module_script = """
Java.perform(function () {

    // 获取该应用加载的类
    var classNames = Java.enumerateLoadedClassesSync();
    
    for (var i = 0; i < classNames.length; i ++){
    
        send('class name: ' + classNames[i]);
        
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
