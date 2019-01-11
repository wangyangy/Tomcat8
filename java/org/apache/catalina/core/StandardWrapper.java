/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.core;

import java.io.PrintStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Stack;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.management.ListenerNotFoundException;
import javax.management.MBeanNotificationInfo;
import javax.management.Notification;
import javax.management.NotificationBroadcasterSupport;
import javax.management.NotificationEmitter;
import javax.management.NotificationFilter;
import javax.management.NotificationListener;
import javax.management.ObjectName;
import javax.servlet.MultipartConfigElement;
import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.SingleThreadModel;
import javax.servlet.UnavailableException;
import javax.servlet.annotation.MultipartConfig;

import org.apache.catalina.Container;
import org.apache.catalina.ContainerServlet;
import org.apache.catalina.Context;
import org.apache.catalina.Globals;
import org.apache.catalina.InstanceEvent;
import org.apache.catalina.InstanceListener;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Wrapper;
import org.apache.catalina.security.SecurityUtil;
import org.apache.catalina.util.InstanceSupport;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.InstanceManager;
import org.apache.tomcat.PeriodicEventListener;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.log.SystemLogHandler;
import org.apache.tomcat.util.modeler.Registry;
import org.apache.tomcat.util.modeler.Util;

/**
 * 该类负责管理一个Servlet.包括Servlet的装载,初始化,卸载,资源回收等.是最底层的容器,没有子容器了.
 * 实现了ServletConfig接口,包含了一个servlet初始化的信息.该类并不会调用Servlet的service方法
 * 而是由StandardWrapperValve调用service方法
 */
@SuppressWarnings("deprecation") // SingleThreadModel
public class StandardWrapper extends ContainerBase
    implements ServletConfig, Wrapper, NotificationEmitter {

    private static final Log log = LogFactory.getLog( StandardWrapper.class );

    protected static final String[] DEFAULT_SERVLET_METHODS = new String[] {
                                                    "GET", "HEAD", "POST" };
    public StandardWrapper() {
        super();
        //基础阀
        swValve=new StandardWrapperValve();
        //管道设置基础阀
        pipeline.setBasic(swValve);
        broadcaster = new NotificationBroadcasterSupport();
    }
    
    // ----------------------------------------------------- Instance Variables

    protected long available = 0L;

    protected final NotificationBroadcasterSupport broadcaster;

    protected final AtomicInteger countAllocated = new AtomicInteger(0);

    //门面的设计模式
    protected final StandardWrapperFacade facade = new StandardWrapperFacade(this);


    /**
     * servlet实例
     */
    protected volatile Servlet instance = null;

    //标记是否已经初始化
    protected volatile boolean instanceInitialized = false;

    @Deprecated
    protected final InstanceSupport instanceSupport = new InstanceSupport(this);

    protected int loadOnStartup = -1;

    //当前Wrapper的映射
    protected final ArrayList<String> mappings = new ArrayList<>();

    //初始化参数
    protected HashMap<String, String> parameters = new HashMap<>();

    protected HashMap<String, String> references = new HashMap<>();

    protected String runAs = null;

    protected long sequenceNumber = 0;

    /**
     * 方便动态加载Servlet对象
     */
    protected String servletClass = null;

    /**
     * 通过该对象判断是单例还是多例的
     */
    protected volatile boolean singleThreadModel = false;

    protected volatile boolean unloading = false;

    //当setvlet多实例的情况下,实例的最大数目
    protected int maxInstances = 20;

    //当前STM的servlet实例数
    protected int nInstances = 0;

    //servlet对象池,实现了SingleThreadModel接口的Servlet成为STM Servlet
    protected Stack<Servlet> instancePool = null;

    protected long unloadDelay = 2000;

    protected boolean isJspServlet;

    protected ObjectName jspMonitorON;

    protected boolean swallowOutput = false;

    //基础阀
    protected StandardWrapperValve swValve;
    protected long loadTime=0;
    protected int classLoadTime=0;

    protected MultipartConfigElement multipartConfigElement = null;

    //异步支持
    protected boolean asyncSupported = false;

    protected boolean enabled = true;

    private boolean overridable = false;

    protected static Class<?>[] classType = new Class[]{ServletConfig.class};

    //参数锁对象
    private final ReentrantReadWriteLock parametersLock =
            new ReentrantReadWriteLock();
    //映射锁对象
    private final ReentrantReadWriteLock mappingsLock =
            new ReentrantReadWriteLock();
    //引用锁对象
    private final ReentrantReadWriteLock referencesLock =
            new ReentrantReadWriteLock();


    // ------------------------------------------------------------- Properties

    @Override
    public boolean isOverridable() {
        return overridable;
    }

    @Override
    public void setOverridable(boolean overridable) {
        this.overridable = overridable;
    }

    @Override
    public long getAvailable() {
        return (this.available);
    }

    @Override
    public void setAvailable(long available) {
        long oldAvailable = this.available;
        if (available > System.currentTimeMillis())
            this.available = available;
        else
            this.available = 0L;
        support.firePropertyChange("available", Long.valueOf(oldAvailable),
                                   Long.valueOf(this.available));
    }

    public int getCountAllocated() {
        return (this.countAllocated.get());
    }


    @Deprecated
    public InstanceSupport getInstanceSupport() {
        return (this.instanceSupport);
    }


    @Override
    public int getLoadOnStartup() {
        if (isJspServlet && loadOnStartup < 0) {
            /*
             * JspServlet must always be preloaded, because its instance is
             * used during registerJMX (when registering the JSP
             * monitoring mbean)
             */
             return Integer.MAX_VALUE;
        } else {
            return (this.loadOnStartup);
        }
    }


    @Override
    public void setLoadOnStartup(int value) {
        int oldLoadOnStartup = this.loadOnStartup;
        this.loadOnStartup = value;
        support.firePropertyChange("loadOnStartup",
                                   Integer.valueOf(oldLoadOnStartup),
                                   Integer.valueOf(this.loadOnStartup));
    }

    public void setLoadOnStartupString(String value) {
        try {
            setLoadOnStartup(Integer.parseInt(value));
        } catch (NumberFormatException e) {
            setLoadOnStartup(0);
        }
    }

    public String getLoadOnStartupString() {
        return Integer.toString( getLoadOnStartup());
    }

    public int getMaxInstances() {
        return (this.maxInstances);
    }

    public void setMaxInstances(int maxInstances) {
        int oldMaxInstances = this.maxInstances;
        this.maxInstances = maxInstances;
        support.firePropertyChange("maxInstances", oldMaxInstances,
                                   this.maxInstances);
    }


    @Override
    public void setParent(Container container) {
        if ((container != null) &&
            !(container instanceof Context))
            throw new IllegalArgumentException
                (sm.getString("standardWrapper.notContext"));
        if (container instanceof StandardContext) {
            swallowOutput = ((StandardContext)container).getSwallowOutput();
            unloadDelay = ((StandardContext)container).getUnloadDelay();
        }
        super.setParent(container);
    }

    @Override
    public String getRunAs() {
        return (this.runAs);
    }

    @Override
    public void setRunAs(String runAs) {
        String oldRunAs = this.runAs;
        this.runAs = runAs;
        support.firePropertyChange("runAs", oldRunAs, this.runAs);
    }

    @Override
    public String getServletClass() {
        return (this.servletClass);
    }

    @Override
    public void setServletClass(String servletClass) {
        String oldServletClass = this.servletClass;
        this.servletClass = servletClass;
        support.firePropertyChange("servletClass", oldServletClass,
                                   this.servletClass);
        if (Constants.JSP_SERVLET_CLASS.equals(servletClass)) {
            isJspServlet = true;
        }
    }

    public void setServletName(String name) {
        setName(name);
    }

    public Boolean isSingleThreadModel() {
        if (singleThreadModel || instance != null) {
            return Boolean.valueOf(singleThreadModel);
        }
        return null;
    }

    @Override
    public boolean isUnavailable() {
        if (!isEnabled())
            return true;
        else if (available == 0L)
            return false;
        else if (available <= System.currentTimeMillis()) {
            available = 0L;
            return false;
        } else
            return true;
    }


    //获取servlet中的方法
    @Override
    public String[] getServletMethods() throws ServletException {
        instance = loadServlet();
        Class<? extends Servlet> servletClazz = instance.getClass();
        if (!javax.servlet.http.HttpServlet.class.isAssignableFrom(
                                                        servletClazz)) {
            return DEFAULT_SERVLET_METHODS;
        }
        HashSet<String> allow = new HashSet<>();
        allow.add("TRACE");
        allow.add("OPTIONS");

        Method[] methods = getAllDeclaredMethods(servletClazz);
        for (int i=0; methods != null && i<methods.length; i++) {
            Method m = methods[i];
            if (m.getName().equals("doGet")) {
                allow.add("GET");
                allow.add("HEAD");
            } else if (m.getName().equals("doPost")) {
                allow.add("POST");
            } else if (m.getName().equals("doPut")) {
                allow.add("PUT");
            } else if (m.getName().equals("doDelete")) {
                allow.add("DELETE");
            }
        }
        String[] methodNames = new String[allow.size()];
        return allow.toArray(methodNames);
    }


    @Override
    public Servlet getServlet() {
        return instance;
    }

    @Override
    public void setServlet(Servlet servlet) {
        instance = servlet;
    }
    
    @Override
    public void setServletSecurityAnnotationScanRequired(boolean b) {}

    // --------------------------------------------------------- Public Methods

    @Override
    public void backgroundProcess() {
        super.backgroundProcess();
        if (!getState().isAvailable())
            return;
        if (getServlet() != null && (getServlet() instanceof PeriodicEventListener)) {
            ((PeriodicEventListener) getServlet()).periodicEvent();
        }
    }


    //提取根异常的方法
    public static Throwable getRootCause(ServletException e) {
        Throwable rootCause = e;
        Throwable rootCauseCheck = null;
        // Extra aggressive rootCause finding
        int loops = 0;
        do {
            loops++;
            rootCauseCheck = rootCause.getCause();
            if (rootCauseCheck != null)
                rootCause = rootCauseCheck;
        } while (rootCauseCheck != null && (loops < 20));
        return rootCause;
    }

    //没有子容器了所以是一个没有实现的方法
    @Override
    public void addChild(Container child) {
        throw new IllegalStateException
            (sm.getString("standardWrapper.notChild"));
    }

    //添加初始化参数
    @Override
    public void addInitParameter(String name, String value) {
        parametersLock.writeLock().lock();
        try {
            parameters.put(name, value);
        } finally {
            parametersLock.writeLock().unlock();
        }
        fireContainerEvent("addInitParameter", name);
    }

    @Deprecated
    @Override
    public void addInstanceListener(InstanceListener listener) {
        instanceSupport.addInstanceListener(listener);
    }

    //添加映射
    @Override
    public void addMapping(String mapping) {
        mappingsLock.writeLock().lock();
        try {
            mappings.add(mapping);
        } finally {
            mappingsLock.writeLock().unlock();
        }
        if(parent.getState().equals(LifecycleState.STARTED))
            fireContainerEvent(ADD_MAPPING_EVENT, mapping);
    }

    @Override
    public void addSecurityReference(String name, String link) {
        referencesLock.writeLock().lock();
        try {
            references.put(name, link);
        } finally {
            referencesLock.writeLock().unlock();
        }
        fireContainerEvent("addSecurityReference", name);
    }


    //分配servlet实例
    @Override
    public Servlet allocate() throws ServletException {
        //还没加载servlet
        if (unloading) {
            throw new ServletException(sm.getString("standardWrapper.unloading", getName()));
        }
        boolean newInstance = false;
        // 单例模式,即没有实现SingleThreadModel接口的servlet
        if (!singleThreadModel) {
            if (instance == null || !instanceInitialized) {
                synchronized (this) {
                    if (instance == null) {
                        try {
                            if (log.isDebugEnabled()) {
                                log.debug("Allocating non-STM instance");
                            }
                            //加载初始化一个servlet
                            instance = loadServlet();
                            newInstance = true;
                            if (!singleThreadModel) {
                                // For non-STM, increment here to prevent a race
                                // condition with unload. Bug 43683, test case
                                // #3
                                countAllocated.incrementAndGet();
                            }
                        } catch (ServletException e) {
                            throw e;
                        } catch (Throwable e) {
                            ExceptionUtils.handleThrowable(e);
                            throw new ServletException(sm.getString("standardWrapper.allocate"), e);
                        }
                    }
                    if (!instanceInitialized) {
                        initServlet(instance);
                    }
                }
            }
            //新生成的实例是多例的模式,则添加到servlet池中
            if (singleThreadModel) {
                if (newInstance) {
                    synchronized (instancePool) {
                        instancePool.push(instance);
                        nInstances++;
                    }
                }
            //否则,计数加一,直接返回
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("  Returning non-STM instance");
                }
                // For new instances, count will have been incremented at the
                // time of creation
                if (!newInstance) {
                    countAllocated.incrementAndGet();
                }
                return instance;
            }
        }
        //如果是多例的模式,即实现了SingleThreadModel接口的Servlet
        synchronized (instancePool) {
        	//nInstances的值小于countAllocated,会一直循环
            while (countAllocated.get() >= nInstances) {
                // 实例数没有超出最大值
                if (nInstances < maxInstances) {
                    try {
                    	//放入servlet对象池中
                        instancePool.push(loadServlet());
                        nInstances++;
                    } catch (ServletException e) {
                        throw e;
                    } catch (Throwable e) {
                        ExceptionUtils.handleThrowable(e);
                        throw new ServletException(sm.getString("standardWrapper.allocate"), e);
                    }
                //如实例数大于设定的最大值,则等待
                } else {
                    try {
                        instancePool.wait();
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }
            }
            if (log.isTraceEnabled()) {
                log.trace("  Returning allocated STM instance");
            }
            countAllocated.incrementAndGet();
            //返回Servlet对象池中的一个对象
            return instancePool.pop();
        }
    }


    //将先前分配的servlet返回栈中
    @Override
    public void deallocate(Servlet servlet) throws ServletException {
        // If not SingleThreadModel, no action is required
        if (!singleThreadModel) {
            countAllocated.decrementAndGet();
            return;
        }
        // Unlock and free this instance
        synchronized (instancePool) {
            countAllocated.decrementAndGet();
            instancePool.push(servlet);
            //如果有等待的线程要通知
            instancePool.notify();
        }
    }


    //查找初始化参数
    @Override
    public String findInitParameter(String name) {
        parametersLock.readLock().lock();
        try {
            return parameters.get(name);
        } finally {
            parametersLock.readLock().unlock();
        }
    }


    @Override
    public String[] findInitParameters() {
        parametersLock.readLock().lock();
        try {
            String results[] = new String[parameters.size()];
            return parameters.keySet().toArray(results);
        } finally {
            parametersLock.readLock().unlock();
        }
    }

    @Override
    public String[] findMappings() {
        mappingsLock.readLock().lock();
        try {
            return mappings.toArray(new String[mappings.size()]);
        } finally {
            mappingsLock.readLock().unlock();
        }
    }

    @Override
    public String findSecurityReference(String name) {
        referencesLock.readLock().lock();
        try {
            return references.get(name);
        } finally {
            referencesLock.readLock().unlock();
        }
    }

    @Override
    public String[] findSecurityReferences() {
        referencesLock.readLock().lock();
        try {
            String results[] = new String[references.size()];
            return references.keySet().toArray(results);
        } finally {
            referencesLock.readLock().unlock();
        }
    }


    //加载,初始化一个servlet实例
    @Override
    public synchronized void load() throws ServletException {
        instance = loadServlet();
        if (!instanceInitialized) {
            initServlet(instance);
        }
        //如果是jspServlet
        if (isJspServlet) {
        	//JMX
            StringBuilder oname = new StringBuilder(getDomain());
            oname.append(":type=JspMonitor");
            oname.append(getWebModuleKeyProperties());
            oname.append(",name=");
            oname.append(getName());
            oname.append(getJ2EEKeyProperties());
            try {
                jspMonitorON = new ObjectName(oname.toString());
                Registry.getRegistry(null, null)
                    .registerComponent(instance, jspMonitorON, null);
            } catch( Exception ex ) {
                log.info("Error registering JSP monitoring with jmx " +
                         instance);
            }
        }
    }


    //加载并且初始化一个Servlet,如果已经有相关的实例则直接返回实例
    public synchronized Servlet loadServlet() throws ServletException {
        if (unloading) {
            throw new ServletException(
                    sm.getString("standardWrapper.unloading", getName()));
        }
        //如果servlet没有实现singleThreadModel接口,并且instance不为空,直接返回instance对象(只有一个实例,直接返回)
        if (!singleThreadModel && (instance != null))
            return instance;
        //记录日志的
        PrintStream out = System.out;
        //开始捕获日志
        if (swallowOutput) {
            SystemLogHandler.startCapture();
        }
        Servlet servlet;
        try {
            long t1=System.currentTimeMillis();
            //如果没有指定Servlet的类型,直接报错
            if (servletClass == null) {
                unavailable(null);
                throw new ServletException
                    (sm.getString("standardWrapper.notClass", getName()));
            }
            //获取实例管理器,就是一个工具类
            InstanceManager instanceManager = ((StandardContext)getParent()).getInstanceManager();
            try {
            	//创建Servlet对象
                servlet = (Servlet) instanceManager.newInstance(servletClass);
            } catch (ClassCastException e) {
                unavailable(null);
                // Restore the context ClassLoader
                throw new ServletException
                    (sm.getString("standardWrapper.notServlet", servletClass), e);
            } catch (Throwable e) {
                e = ExceptionUtils.unwrapInvocationTargetException(e);
                ExceptionUtils.handleThrowable(e);
                unavailable(null);
                if(log.isDebugEnabled()) {
                    log.debug(sm.getString("standardWrapper.instantiate", servletClass), e);
                }
                // Restore the context ClassLoader
                throw new ServletException
                    (sm.getString("standardWrapper.instantiate", servletClass), e);
            }
            //表示当前servlet对象是不是需要使用multipart/form-data MIME类型进行请求。
            if (multipartConfigElement == null) {
                MultipartConfig annotation =
                        servlet.getClass().getAnnotation(MultipartConfig.class);
                if (annotation != null) {
                    multipartConfigElement =
                            new MultipartConfigElement(annotation);
                }
            }
            // 检查是不是ContainerServlet类型的servlet,ContainerServlet类型的Servlet可以访问Catalina内部的功能
            // 普通的servlet(即程序员编写的servlet)是没有权限访问tomcat内部的资源的
            if ((servlet instanceof ContainerServlet) &&
                    (isContainerProvidedServlet(servletClass) ||
                            ((Context) getParent()).getPrivileged() )) {
                ((ContainerServlet) servlet).setWrapper(this);
            }
            classLoadTime=(int) (System.currentTimeMillis() -t1);
            //如果实现了SingleThreadModel接口
            if (servlet instanceof SingleThreadModel) {
            	//初始化STM Servlet对象池
                if (instancePool == null) {
                    instancePool = new Stack<>();
                }
                //标记为true
                singleThreadModel = true;
            }
            //初始化servlet
            initServlet(servlet);
            //通知已经加载
            fireContainerEvent("load", this);
            loadTime=System.currentTimeMillis() -t1;
        } finally {
            if (swallowOutput) {
            	//记录日志
                String log = SystemLogHandler.stopCapture();
                if (log != null && log.length() > 0) {
                    if (getServletContext() != null) {
                        getServletContext().log(log);
                    } else {
                        out.println(log);
                    }
                }
            }
        }
        return servlet;
    }

    @Override
    public void servletSecurityAnnotationScan() throws ServletException {}

    //初始化servlet
    private synchronized void initServlet(Servlet servlet)
            throws ServletException {
        if (instanceInitialized && !singleThreadModel) return;

        // Call the initialization method of this servlet
        try {
            instanceSupport.fireInstanceEvent(InstanceEvent.BEFORE_INIT_EVENT,
                                              servlet);
            //如果有安全认证,需要使用doAsPrivilege进行初始化
            if( Globals.IS_SECURITY_ENABLED) {
                boolean success = false;
                try {
                	//传入了StandardWrapperFacade外观对象facade
                    Object[] args = new Object[] { facade };
                    SecurityUtil.doAsPrivilege("init",
                                               servlet,
                                               classType,
                                               args);
                    success = true;
                } finally {
                    if (!success) {
                        // destroy() will not be called, thus clear the reference now
                        SecurityUtil.remove(servlet);
                    }
                }
            //直接进行初始化
            } else {
            	//参数是一个ServletConfig类型的对象,facde对象实现了ServletConfig接口,但里面具体的方法是调用StandardWrapper中的方法
            	//因为StandardWrapper也实现了ServletConfig接口,构造facde对象的时候,this作为参数传了进去
            	//这里为什么不把this穿进去而是还特地的弄了一个Facde,为的就是把this中大部分public方法对程序员隐藏,为了安全
                servlet.init(facade);
            }
            //标记已经进完成初始化
            instanceInitialized = true;
            instanceSupport.fireInstanceEvent(InstanceEvent.AFTER_INIT_EVENT,
                                              servlet);
        } catch (UnavailableException f) {
            instanceSupport.fireInstanceEvent(InstanceEvent.AFTER_INIT_EVENT,
                                              servlet, f);
            unavailable(f);
            throw f;
        } catch (ServletException f) {
            instanceSupport.fireInstanceEvent(InstanceEvent.AFTER_INIT_EVENT,
                                              servlet, f);
            // If the servlet wanted to be unavailable it would have
            // said so, so do not call unavailable(null).
            throw f;
        } catch (Throwable f) {
            ExceptionUtils.handleThrowable(f);
            getServletContext().log("StandardWrapper.Throwable", f );
            instanceSupport.fireInstanceEvent(InstanceEvent.AFTER_INIT_EVENT,
                                              servlet, f);
            // If the servlet wanted to be unavailable it would have
            // said so, so do not call unavailable(null).
            throw new ServletException
                (sm.getString("standardWrapper.initException", getName()), f);
        }
    }

    //删除初始化参数
    @Override
    public void removeInitParameter(String name) {
        parametersLock.writeLock().lock();
        try {
            parameters.remove(name);
        } finally {
            parametersLock.writeLock().unlock();
        }
        fireContainerEvent("removeInitParameter", name);
    }


    @Deprecated
    @Override
    public void removeInstanceListener(InstanceListener listener) {
        instanceSupport.removeInstanceListener(listener);
    }

    //删除映射
    @Override
    public void removeMapping(String mapping) {
        mappingsLock.writeLock().lock();
        try {
            mappings.remove(mapping);
        } finally {
            mappingsLock.writeLock().unlock();
        }
        if(parent.getState().equals(LifecycleState.STARTED))
            fireContainerEvent(REMOVE_MAPPING_EVENT, mapping);
    }

    @Override
    public void removeSecurityReference(String name) {
        referencesLock.writeLock().lock();
        try {
            references.remove(name);
        } finally {
            referencesLock.writeLock().unlock();
        }
        fireContainerEvent("removeSecurityReference", name);
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (getParent() != null) {
            sb.append(getParent().toString());
            sb.append(".");
        }
        sb.append("StandardWrapper[");
        sb.append(getName());
        sb.append("]");
        return (sb.toString());
    }


    @Override
    public void unavailable(UnavailableException unavailable) {
        getServletContext().log(sm.getString("standardWrapper.unavailable", getName()));
        if (unavailable == null)
            setAvailable(Long.MAX_VALUE);
        else if (unavailable.isPermanent())
            setAvailable(Long.MAX_VALUE);
        else {
            int unavailableSeconds = unavailable.getUnavailableSeconds();
            if (unavailableSeconds <= 0)
                unavailableSeconds = 60;        // Arbitrary default
            setAvailable(System.currentTimeMillis() +
                         (unavailableSeconds * 1000L));
        }
    }


    //卸载所有servlet实例
    @Override
    public synchronized void unload() throws ServletException {
        // Nothing to do if we have never loaded the instance
        if (!singleThreadModel && (instance == null))
            return;
        unloading = true;
        // Loaf a while if the current instance is allocated
        // (possibly more than once if non-STM)
        if (countAllocated.get() > 0) {
            int nRetries = 0;
            long delay = unloadDelay / 20;
            while ((nRetries < 21) && (countAllocated.get() > 0)) {
                if ((nRetries % 10) == 0) {
                    log.info(sm.getString("standardWrapper.waiting",
                                          countAllocated.toString(),
                                          getName()));
                }
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    // Ignore
                }
                nRetries++;
            }
        }

        if (instanceInitialized) {
            PrintStream out = System.out;
            if (swallowOutput) {
                SystemLogHandler.startCapture();
            }
            // Call the servlet destroy() method
            try {
                instanceSupport.fireInstanceEvent
                  (InstanceEvent.BEFORE_DESTROY_EVENT, instance);

                if( Globals.IS_SECURITY_ENABLED) {
                    try {
                        SecurityUtil.doAsPrivilege("destroy",
                                                   instance);
                    } finally {
                        SecurityUtil.remove(instance);
                    }
                } else {
                    instance.destroy();
                }
                instanceSupport.fireInstanceEvent
                  (InstanceEvent.AFTER_DESTROY_EVENT, instance);

            } catch (Throwable t) {
                t = ExceptionUtils.unwrapInvocationTargetException(t);
                ExceptionUtils.handleThrowable(t);
                instanceSupport.fireInstanceEvent
                  (InstanceEvent.AFTER_DESTROY_EVENT, instance, t);
                instance = null;
                instancePool = null;
                nInstances = 0;
                fireContainerEvent("unload", this);
                unloading = false;
                throw new ServletException
                    (sm.getString("standardWrapper.destroyException", getName()),
                     t);
            } finally {
                // Annotation processing
                if (!((Context) getParent()).getIgnoreAnnotations()) {
                    try {
                        ((Context)getParent()).getInstanceManager().destroyInstance(instance);
                    } catch (Throwable t) {
                        ExceptionUtils.handleThrowable(t);
                        log.error(sm.getString("standardWrapper.destroyInstance", getName()), t);
                    }
                }
                // Write captured output
                if (swallowOutput) {
                    String log = SystemLogHandler.stopCapture();
                    if (log != null && log.length() > 0) {
                        if (getServletContext() != null) {
                            getServletContext().log(log);
                        } else {
                            out.println(log);
                        }
                    }
                }
            }
        }

        // Deregister the destroyed instance
        instance = null;
        instanceInitialized = false;
        if (isJspServlet && jspMonitorON != null ) {
            Registry.getRegistry(null, null).unregisterComponent(jspMonitorON);
        }
        if (singleThreadModel && (instancePool != null)) {
            try {
                while (!instancePool.isEmpty()) {
                    Servlet s = instancePool.pop();
                    if (Globals.IS_SECURITY_ENABLED) {
                        try {
                            SecurityUtil.doAsPrivilege("destroy", s);
                        } finally {
                            SecurityUtil.remove(s);
                        }
                    } else {
                        s.destroy();
                    }
                    // Annotation processing
                    if (!((Context) getParent()).getIgnoreAnnotations()) {
                       ((StandardContext)getParent()).getInstanceManager().destroyInstance(s);
                    }
                }
            } catch (Throwable t) {
                t = ExceptionUtils.unwrapInvocationTargetException(t);
                ExceptionUtils.handleThrowable(t);
                instancePool = null;
                nInstances = 0;
                unloading = false;
                fireContainerEvent("unload", this);
                throw new ServletException
                    (sm.getString("standardWrapper.destroyException",
                                  getName()), t);
            }
            instancePool = null;
            nInstances = 0;
        }

        singleThreadModel = false;
        unloading = false;
        fireContainerEvent("unload", this);
    }

    // -------------------------------------------------- ServletConfig Methods
    //获取初始化参数
    @Override
    public String getInitParameter(String name) {
        return (findInitParameter(name));
    }

    @Override
    public Enumeration<String> getInitParameterNames() {
        parametersLock.readLock().lock();
        try {
            return Collections.enumeration(parameters.keySet());
        } finally {
            parametersLock.readLock().unlock();
        }
    }


    @Override
    public ServletContext getServletContext() {
        if (parent == null)
            return (null);
        else if (!(parent instanceof Context))
            return (null);
        else
            return (((Context) parent).getServletContext());
    }


    @Override
    public String getServletName() {
        return (getName());
    }

    public long getProcessingTime() {
        return swValve.getProcessingTime();
    }

    public long getMaxTime() {
        return swValve.getMaxTime();
    }

    public long getMinTime() {
        return swValve.getMinTime();
    }

    public int getRequestCount() {
        return swValve.getRequestCount();
    }

    public int getErrorCount() {
        return swValve.getErrorCount();
    }

    @Override
    public void incrementErrorCount(){
        swValve.incrementErrorCount();
    }

    public long getLoadTime() {
        return loadTime;
    }

    public int getClassLoadTime() {
        return classLoadTime;
    }

    @Override
    public MultipartConfigElement getMultipartConfigElement() {
        return multipartConfigElement;
    }

    @Override
    public void setMultipartConfigElement(
            MultipartConfigElement multipartConfigElement) {
        this.multipartConfigElement = multipartConfigElement;
    }

    @Override
    public boolean isAsyncSupported() {
        return asyncSupported;
    }

    @Override
    public void setAsyncSupported(boolean asyncSupported) {
        this.asyncSupported = asyncSupported;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    // -------------------------------------------------------- Package Methods


    // -------------------------------------------------------- protected Methods

    protected boolean isContainerProvidedServlet(String classname) {
        if (classname.startsWith("org.apache.catalina.")) {
            return (true);
        }
        try {
            Class<?> clazz =
                this.getClass().getClassLoader().loadClass(classname);
            return (ContainerServlet.class.isAssignableFrom(clazz));
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            return (false);
        }
    }


    //将祖先和自己的方法通过反射的方法获取
    protected Method[] getAllDeclaredMethods(Class<?> c) {
        if (c.equals(javax.servlet.http.HttpServlet.class)) {
            return null;
        }
        Method[] parentMethods = getAllDeclaredMethods(c.getSuperclass());
        Method[] thisMethods = c.getDeclaredMethods();
        if (thisMethods.length == 0) {
            return parentMethods;
        }
        if ((parentMethods != null) && (parentMethods.length > 0)) {
            Method[] allMethods =
                new Method[parentMethods.length + thisMethods.length];
            System.arraycopy(parentMethods, 0, allMethods, 0,
                             parentMethods.length);
            System.arraycopy(thisMethods, 0, allMethods, parentMethods.length,
                             thisMethods.length);

            thisMethods = allMethods;
        }
        return thisMethods;
    }


    // ------------------------------------------------------ Lifecycle Methods

    //启动组件
    @Override
    protected synchronized void startInternal() throws LifecycleException {
        // Send j2ee.state.starting notification
        if (this.getObjectName() != null) {
            Notification notification = new Notification("j2ee.state.starting",
                                                        this.getObjectName(),
                                                        sequenceNumber++);
            broadcaster.sendNotification(notification);
        }
        // Start up this component
        super.startInternal();
        setAvailable(0L);
        // Send j2ee.state.running notification
        if (this.getObjectName() != null) {
            Notification notification =
                new Notification("j2ee.state.running", this.getObjectName(),
                                sequenceNumber++);
            broadcaster.sendNotification(notification);
        }
    }


    //停止组件
    @Override
    protected synchronized void stopInternal() throws LifecycleException {
        setAvailable(Long.MAX_VALUE);
        // Send j2ee.state.stopping notification
        if (this.getObjectName() != null) {
            Notification notification =
                new Notification("j2ee.state.stopping", this.getObjectName(),
                                sequenceNumber++);
            broadcaster.sendNotification(notification);
        }
        // Shut down our servlet instance (if it has been initialized)
        try {
            unload();
        } catch (ServletException e) {
            getServletContext().log(sm.getString
                      ("standardWrapper.unloadException", getName()), e);
        }

        // Shut down this component
        super.stopInternal();
        // Send j2ee.state.stopped notification
        if (this.getObjectName() != null) {
            Notification notification =
                new Notification("j2ee.state.stopped", this.getObjectName(),
                                sequenceNumber++);
            broadcaster.sendNotification(notification);
        }
        // Send j2ee.object.deleted notification
        Notification notification =
            new Notification("j2ee.object.deleted", this.getObjectName(),
                            sequenceNumber++);
        broadcaster.sendNotification(notification);
    }


    @Override
    protected String getObjectNameKeyProperties() {
        StringBuilder keyProperties =
            new StringBuilder("j2eeType=Servlet");
        keyProperties.append(getWebModuleKeyProperties());
        keyProperties.append(",name=");
        String name = getName();
        if (Util.objectNameValueNeedsQuote(name)) {
            name = ObjectName.quote(name);
        }
        keyProperties.append(name);
        keyProperties.append(getJ2EEKeyProperties());
        return keyProperties.toString();
    }


    private String getWebModuleKeyProperties() {
        StringBuilder keyProperties = new StringBuilder(",WebModule=//");
        String hostName = getParent().getParent().getName();
        if (hostName == null) {
            keyProperties.append("DEFAULT");
        } else {
            keyProperties.append(hostName);
        }
        String contextName = ((Context) getParent()).getName();
        if (!contextName.startsWith("/")) {
            keyProperties.append('/');
        }
        keyProperties.append(contextName);

        return keyProperties.toString();
    }

    private String getJ2EEKeyProperties() {
        StringBuilder keyProperties = new StringBuilder(",J2EEApplication=");
        StandardContext ctx = null;
        if (parent instanceof StandardContext) {
            ctx = (StandardContext) getParent();
        }
        if (ctx == null) {
            keyProperties.append("none");
        } else {
            keyProperties.append(ctx.getJ2EEApplication());
        }
        keyProperties.append(",J2EEServer=");
        if (ctx == null) {
            keyProperties.append("none");
        } else {
            keyProperties.append(ctx.getJ2EEServer());
        }
        return keyProperties.toString();
    }

    @Deprecated
    public boolean isStateManageable() {
        return false;
    }


    /* Remove a JMX notificationListener
     * @see javax.management.NotificationEmitter#removeNotificationListener(javax.management.NotificationListener, javax.management.NotificationFilter, java.lang.Object)
     */
    @Override
    public void removeNotificationListener(NotificationListener listener,
            NotificationFilter filter, Object object) throws ListenerNotFoundException {
        broadcaster.removeNotificationListener(listener,filter,object);
    }

    protected MBeanNotificationInfo[] notificationInfo;

    /* Get JMX Broadcaster Info
     * @TODO use StringManager for international support!
     * @TODO This two events we not send j2ee.state.failed and j2ee.attribute.changed!
     * @see javax.management.NotificationBroadcaster#getNotificationInfo()
     */
    @Override
    public MBeanNotificationInfo[] getNotificationInfo() {

        if(notificationInfo == null) {
            notificationInfo = new MBeanNotificationInfo[]{
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.object.created"},
                    Notification.class.getName(),
                    "servlet is created"
                    ),
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.state.starting"},
                    Notification.class.getName(),
                    "servlet is starting"
                    ),
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.state.running"},
                    Notification.class.getName(),
                    "servlet is running"
                    ),
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.state.stopped"},
                    Notification.class.getName(),
                    "servlet start to stopped"
                    ),
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.object.stopped"},
                    Notification.class.getName(),
                    "servlet is stopped"
                    ),
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.object.deleted"},
                    Notification.class.getName(),
                    "servlet is deleted"
                    )
            };
        }
        return notificationInfo;
    }

    /* Add a JMX-NotificationListener
     */
    @Override
    public void addNotificationListener(NotificationListener listener,
            NotificationFilter filter, Object object) throws IllegalArgumentException {
        broadcaster.addNotificationListener(listener,filter,object);
    }

    /**
     * Remove a JMX-NotificationListener
     * @see javax.management.NotificationBroadcaster#removeNotificationListener(javax.management.NotificationListener)
     */
    @Override
    public void removeNotificationListener(NotificationListener listener)
        throws ListenerNotFoundException {
        broadcaster.removeNotificationListener(listener);
    }
}
