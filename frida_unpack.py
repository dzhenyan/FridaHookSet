# -*- coding:utf-8 -*-
# coding=utf-8
import frida
import sys


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


"""
需要Hook的OpenMemory函数名称
android_9_0_arm = '_ZN3art13DexFileLoader10OpenCommonEPKhjS2_jRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE '
android_7_0_arm = '_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_'
android_6_0_arm = '_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_'
android 6 7 8 9版本需要 Hook libart.so
android 10 版本需要 Hooklibdexfile.so
"""

package_name = 'com.iCitySuzhou.suzhou001'
print("dex 导出目录为: /data/data/%s" % (package_name))
device = frida.get_remote_device()
pid = device.spawn(package_name)
session = device.attach(pid)
src = """
Interceptor.attach(Module.findExportByName("libart.so", "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_"), {
    onEnter: function (args) {

        var begin = args[1]

        console.log("magic : " + Memory.readUtf8String(begin))

        var address = parseInt(begin,16) + 0x20
        var dex_size = Memory.readInt(ptr(address))
        console.log("dex_size :" + dex_size)

        var file = new File("/data/data/%s/" + dex_size + ".dex", "wb")
        file.write(Memory.readByteArray(begin, dex_size))
        file.flush()
        file.close()
        var send_data = {}
        send_data.base = parseInt(begin,16)
        send_data.size = dex_size
        send(send_data)
    },
    onLeave: function (retval) {
    
        if (retval.toInt32() > 0) {
        }
    }
});
""" % (package_name)

script = session.create_script(src)

script.on("message", on_message)

script.load()
device.resume(pid)
sys.stdin.read()
