# XlogDecoder
微信Mars中的xlog文件解密程序java版本，且增加支持多线程调用

## 快速使用

参考代码位于 src/com/meizu/sysmonitor/Main.java

使用方式：
1. 你可以注入环境变量 XLOG_PRIV_KEY 和 XLOG_PUB_KEY 两个变量，分别对应私匙和公匙
2. 你也可以修改java代码
3. 使用的时候，看你是直接把xlog文件路径，注入到代码中，还是通过命令行传参


以命令行传参为例：

```bash
java -jar XlogDecoder.jar text.xlog
```

就可以解码xlog日志文件了

## 更新日志

* 新增convertStream方法，把inputStream，转换成outStream 【使用场景，流数据处理】
```java 
public static void convertStream(InputStream inStream, OutputStream ost) 
```


### 友情链接
微信Mars库源码 [https://github.com/Tencent/mars/](!https://github.com/Tencent/mars/)
