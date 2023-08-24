# 线程变量

## ThreadLocal常用api以及使用


https://zhuanlan.zhihu.com/p/576975260
```java
public class ThreadLocalDemo {

    // 定义一个String类型的线程变量
    static ThreadLocal<Integer> context = new ThreadLocal<>();

    public static void main(String[] args) {
        // 设置线程变量的值
        context.set(1000);

        // 从线程变量中取出值
        Integer id = context.get();
        System.out.println(id);

        // 删除线程变量中的值
        context.remove();
        // 输出null
        System.out.println(context.get());
    }
}
```
ThreadLocal的用法非常简单，创建ThreadLocal的时候指定泛型类型，然后就是赋值、取值、删除值的操作。
不同线程之间，ThreadLocal数据是隔离的，测试一下：
```java
public class ThreadLocalDemo {
    // 1. 创建ThreadLocal
    static ThreadLocal<Integer> threadLocal = new ThreadLocal<>();

    public static void main(String[] args) {
        IntStream.range(0, 5).forEach(i -> {
          	// 创建5个线程，分别给threadLocal赋值、取值
            new Thread(() -> {
                // 2. 给ThreadLocal赋值
                threadLocal.set(i);
                // 3. 从ThreadLocal中取值
                System.out.println(Thread.currentThread().getName()
                        + "," + threadLocal.get());
            }).start();
        });
    }

}
```

可以看出不同线程之间的ThreadLocal数据相互隔离，互不影响，这样的实现效果有哪些应用场景呢？

ThreadLocal的应用场景主要分为两类：
1.避免对象在方法之间层层传递，打破层次间约束。
比如用户信息，在很多地方都需要用到，层层往下传递，比较麻烦。这时候就可以把用户信息放到ThreadLocal中，需要的地方可以直接使用。拷贝对象副本，减少初始化操作，并保证数据安全。
比如数据库连接、Spring事务管理、SimpleDataFormat格式化日期，都是使用的ThreadLocal，即避免每个线程都初始化一个对象，又保证了多线程下的数据安全。

2.使用ThreadLocal保证SimpleDataFormat格式化日期的线程安全，代码类似下面这样：

```java
/**
 * @author 一灯架构
 * @apiNote ThreadLocal示例
 **/
public class ThreadLocalDemo {
    // 1. 创建ThreadLocal
    static ThreadLocal<SimpleDateFormat> threadLocal =
            ThreadLocal.withInitial(() -> new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"));


    public static void main(String[] args) {
        IntStream.range(0, 5).forEach(i -> {
            // 创建5个线程，分别从threadLocal取出SimpleDateFormat，然后格式化日期
            new Thread(() -> {
                try {
                    System.out.println(threadLocal.get().parse("2022-11-11 00:00:00"));
                } catch (ParseException e) {
                    throw new RuntimeException(e);
                }
            }).start();
        });
    }

}
```


```java
import java.util.concurrent.atomic.AtomicInteger;

public class ThreadId {
    // Atomic integer containing the next thread ID to be assigned
    private static final AtomicInteger nextId = new AtomicInteger(0);

    // Thread local variable containing each thread's ID
    private static final ThreadLocal<Integer> threadId =
        new ThreadLocal<Integer>() {
            @Override protected Integer initialValue() {
                return nextId.getAndIncrement();
        }
    };

    // Returns the current thread's unique ID, assigning it if necessary
    public static int get() {
        return threadId.get();
    }
}
```
```java
public final class TestThreadId extends Thread {

    // number of times to create threads and gather their ids
    private static final int ITERATIONCOUNT = 50;

    // Threads constructed per iteration. ITERATIONCOUNT=50 and
    // THREADCOUNT=50 takes about one second on a sun Blade 1000 (2x750mhz)
    private static final int THREADCOUNT = 50;

    // The thread local storage object for holding per-thread ids
    private static ThreadId id = new ThreadId();

    // Holds the per-thread so main method thread can collect it. JMM
    // guarantees this is valid after this thread joins main method thread.
    private int value;

    private synchronized int getIdValue() {
        return value;
    }

    // Each child thread just publishes its id value for validation
    public void run() {
        value = id.get();
    }

    public static void main(String args[]) throws Throwable {

        // holds true corresponding to a used id value
        boolean check[] = new boolean[THREADCOUNT*ITERATIONCOUNT];

        // the test threads
        TestThreadId u[] = new TestThreadId[THREADCOUNT];

        for (int i = 0; i < ITERATIONCOUNT; i++) {
            // Create and start the threads
            for (int t=0;t<THREADCOUNT;t++) {
                u[t] = new TestThreadId();
                u[t].start();
            }
            // Join with each thread and get/check its id
            for (int t=0;t<THREADCOUNT;t++) {
                try {
                    u[t].join();
                } catch (InterruptedException e) {
                     throw new RuntimeException(
                        "TestThreadId: Failed with unexpected exception" + e);
                }
                try {
                    if (check[u[t].getIdValue()]) {
                        throw new RuntimeException(
                            "TestThreadId: Failed with duplicated id: " +
                                u[t].getIdValue());
                    } else {
                        check[u[t].getIdValue()] = true;
                    }
                } catch (Exception e) {
                    throw new RuntimeException(
                        "TestThreadId: Failed with unexpected id value" + e);
                }
            }
        }
    } // main
} // TestThreadId
```

## 源码解析
ThreadLocal是线程本地变量，就是线程的私有变量，不同线程之间相互隔离，无法共享，相当于每个线程拷贝了一份变量的副本。

目的就是在多线程环境中，无需加锁，也能保证数据的安全性。



## 使用常见




## 常用陷阱



## 


https://xie.infoq.cn/article/baf3b63fab9e932422ec56edf