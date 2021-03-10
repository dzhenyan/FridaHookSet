import frida
import sys

module_script = """
Java.perform(function () {

    // 获取到getAuthString函数的绝对地址
    var getAuthString_absulate_add = Module.getExportByName('libnative-lib.so', 'getAuthString');
    
    //计算出so文件的基地址，0x66500为so文件中getAuthString函数的相对地址
    var native_lib_base_add = parseInt(getAuthString_absulate_add) - parseInt('0x66500');
    
    send('native_lib_base_add: ' + ptr(native_lib_base_add));
    
    //用libnative-lib.so基地址加上MD5:MD5()的偏移量 就是MD5:MD5（）在内存中的地址
    //md5_init_address 是int型
    var md5_init_address = ptr(native_lib_base_add + parseInt('0x32168));
    
    send('md5_init_address: ' + md5_init_address);
    
    //hook MD5:MD5()
    try{
        Interceptor.attach(md5_init_address,
        {
            OnEnter: function(args) {
                send("---open("+args[0]+", "+args[1]+")");
                send("---open("+Memory.readUtf8String(args[0])+","+args[1]+")");
            },
            OnLeave: function(retval) {
                //send("retval: " + retval);
            }
        });
    }
    catch(err) {
        console.log(err.description);
    }
    
    //b64_encode address
    var b64_encode_add = ptr(native_lib_base_add + parseInt('0x31DB8'));
    send('b64_encode_add:' + b64_encode_add);
    
    Interceptor.attach(b64_encode_add,
        {
            OnEnter: function(args) {
                send("b64_encode ori: " + Memory.readUtf8String(args[0]));
            },
            OnLeave: function(retval) {
                //send("retval: " + retval);
            }
        });
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
device = frida.get_usb_device()
pid = device.spawn([':com.coolapk.market'])
process = device.attach(pid)
script = process.create_script(module_script)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
device.resume(pid)
sys.stdin.read()
