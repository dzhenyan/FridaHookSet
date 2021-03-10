import frida, sys

pakeage = 'com.yaotong.crackme'


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


open_memory_9 = '_ZNHart....'
# OpenMemory 在libart.so中  art虚拟机（安卓5） davlink虚拟机（安卓4）
# Hook OpenMemory的导出方法名
# 用IDA 打开libart.so 查看OpenMemory的导出方法名
# OpenMemory的第一个参数是dex文件在内存中的起始位置
# 根据dex的文件格式 从起始位置开始 第32个字节 是dex文件的大小
# 知道dex的起始位置和整个文件的大小，只需把这段内存dump出来即可
# 适用于 安卓 6 7 8 9

src = """
//代码在android os: 7.1.2上测试通过
//32位的libart.so 
var openMemory_address = Module.findExportByName("libart.so", "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_");

send("openMemory_address: " + openMemory_address);

Interceptor.attach(openMemory_address, {

    onEnter: function (args) {
      
        //dex起始位置
        var begin = args[1]
        
        console.log(begin);
        
        //打印magic
        send("magic : " + Memory.readUtf8String(begin))
        
        //dex fileSize 地址
        var address = parseInt(begin,16) + 0x20
        
        //dex 大小
        var dex_size = Memory.readInt(ptr(address))

        send("dex_size :" + dex_size)
        
        //dump dex 到/data/data/pkg/目录下
        var file = new File("/sdcard/unpack/" + dex_size + ".dex", "wb")
        
        file.write(Memory.readByteArray(begin, dex_size))
        
        file.flush()
        
        file.close()
        
    },
    onLeave: function (retval) {
    
        if (retval.toInt32() > 0) {
            
        }
    }
});



//64位的libart.so 
var openMemory_address = Module.findExportByName("libart.so","_ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_");

send("openMemory_address: " + openMemory_address);

Interceptor.attach(openMemory_address, {

    onEnter: function (args) {
      
        //dex起始位置
        //64位这里获取的args[1]有bug,这里直接读取r0寄存器
        var begin = this.context.x0
        
        //console.log(this.context.x0);
        //打印magic
        send("magic : " + Memory.readUtf8String(begin))
        
        //dex fileSize 地址
        var address = parseInt(begin,16) + 0x20
        
        //dex 大小
        var dex_size = Memory.readInt(ptr(address))

        send("dex_size :" + dex_size)
        //dump dex 到/data/data/pkg/目录下
        var file = new File("/sdcard/unpack/" + dex_size + ".dex", "wb")
        
        file.write(Memory.readByteArray(begin, dex_size))
        
        file.flush()
        
        file.close()
    },
    onLeave: function (retval) {
    
        if (retval.toInt32() > 0) {
            
        }
    }
});
"""
