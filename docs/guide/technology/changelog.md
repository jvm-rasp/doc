# 版本迭代

## 1.1.0【2022-10】
#### Enhancement
+ [attach] 新增jrasp-attach工程(Golang)，支持手动注入、查看hook类、更新模块参数和卸载RASP
+ [agent] agent依赖的bridge打包时指定，防止加载错误依赖
+ [agent] 去掉logback/sl4j，使用原生jul ，减少不安全的依赖
+ [agent] 去掉内置jetty，使用原生socket
+ [agent] 去掉java-agent的json日志格式，并修改filebeat的日志分割grok表达式
+ [module] 上下文对象优化为context对象
+ [module] module统一参数更新接口
+ [project] 将jrasp-agent、jrasp-module、jrasp-attach和jrasp-daemon等工程合并，统一编译打包
+ [project] 全面兼容 windows、linux、mac
+ [agent] 优化类匹配机制，全局唯一transform实例，减少stw时间
### BugFix
+ [agent] jar包文件名称增加版本号，解决jar包文件句柄清除问题
+ [module] 替换 @Resource 注解，解决与javax包类的冲突
+ [agent] 解决jvm-sandbox抛出异常时的内存泄漏 bug （jvm-sandbox 已经合入补丁）
+ [jetty module] 解决 http input.read方法重复hook问题 （openrasp官方已经确认该问题）
+ [xxe module] 解决dom4j方法重复hook问题 （openrasp官方已经确认该问题）

### TODO

+ [agent] 使用InheritableThreadLocal代替ThreadLocal防止线程注入 （存在内存泄漏，暂缓）


## 1.0.8 【2022-08】（内部测试版本）
#### Enhancement
+ [module] 增加多个安全模块
+ [daemon] 进程扫描优化
+ [daemon] 防止启动多个守护进程

## 1.0.7 【2022-07】（用户使用的稳定版本）
#### Enhancement
+ [daemon] 上报配置更新时间
+ [daemon] daemon启动上报nacos初始化的状态和注册的服务ip
+ [daemon] 发现无法连接nacos时，自动重启，24小时检测一次

#### BugFix
+ [daemon] 修复软刷新panic
+ [daemon] 删除获取依赖的功能，由安全插件自行上报

## 1.0.6 【2022-06】
#### BugFix
+ [daemon] 使用 os.RemoveAll 删除Java进程文件夹

## 1.0.5 【2022-05】
+ [daemon]插件以配置文件为准，配置文件中没有的，删除磁盘上的
+ [daemon]注入后增加软刷新功能和参数更新功能

## 1.0.4 【2022-04】 （开源版本）
+ [agent] 增加native方法hook
+ [daemon] 支持对多个Java进程注入，每个Java进程独立的数据目录
