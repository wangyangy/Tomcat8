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
package org.apache.catalina.startup;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.net.ConnectException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.logging.LogManager;

import org.apache.catalina.Container;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Server;
import org.apache.catalina.security.SecurityConfig;
import org.apache.juli.ClassLoaderLogManager;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.digester.Digester;
import org.apache.tomcat.util.digester.Rule;
import org.apache.tomcat.util.digester.RuleSet;
import org.apache.tomcat.util.log.SystemLogHandler;
import org.apache.tomcat.util.res.StringManager;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;


/**
 * 该类负责启动关闭server对象,加载tomcat配置文件server.xml,该类包含digester对象,用来解析xml文件
 * 该类中封装了server对象,
 * Startup/Shutdown shell program for Catalina.  The following command line
 * options are recognized:
 * <ul>
 * <li><b>-config {pathname}</b> - Set the pathname of the configuration file
 *     to be processed.  If a relative path is specified, it will be
 *     interpreted as relative to the directory pathname specified by the
 *     "catalina.base" system property.   [conf/server.xml]</li>
 * <li><b>-help</b>      - Display usage information.</li>
 * <li><b>-nonaming</b>  - Disable naming support.</li>
 * <li><b>configtest</b> - Try to test the config</li>
 * <li><b>start</b>      - Start an instance of Catalina.</li>
 * <li><b>stop</b>       - Stop the currently running instance of Catalina.</li>
 * </ul>
 *
 * @author Craig R. McClanahan
 * @author Remy Maucherat
 */
public class Catalina {


    /**
     * The string manager for this package.
     */
    protected static final StringManager sm =
        StringManager.getManager(Constants.Package);


    // ----------------------------------------------------- Instance Variables

    /**
     * Use await.
     */
    protected boolean await = false;

    /**
     * Pathname to the server configuration file.
     */
    protected String configFile = "conf/server.xml";

    // XXX Should be moved to embedded
    /**
     * The shared extensions class loader for this server.
     */
    protected ClassLoader parentClassLoader =
        Catalina.class.getClassLoader();


    /**
     * The server component we are starting or stopping.
     */
    protected Server server = null;


    /**
     * Use shutdown hook flag.
     */
    protected boolean useShutdownHook = true;


    /**
     * Shutdown hook.
     */
    protected Thread shutdownHook = null;


    /**
     * Is naming enabled ?
     */
    protected boolean useNaming = true;


    /**
     * Prevent duplicate loads.
     */
    protected boolean loaded = false;


    // ----------------------------------------------------------- Constructors

    public Catalina() {
        setSecurityProtection();
        ExceptionUtils.preload();
    }


    // ------------------------------------------------------------- Properties

    public void setConfigFile(String file) {
        configFile = file;
    }


    public String getConfigFile() {
        return configFile;
    }


    public void setUseShutdownHook(boolean useShutdownHook) {
        this.useShutdownHook = useShutdownHook;
    }


    public boolean getUseShutdownHook() {
        return useShutdownHook;
    }


    /**
     * Set the shared extensions class loader.
     *
     * @param parentClassLoader The shared extensions class loader.
     */
    public void setParentClassLoader(ClassLoader parentClassLoader) {
        this.parentClassLoader = parentClassLoader;
    }

    public ClassLoader getParentClassLoader() {
        if (parentClassLoader != null) {
            return (parentClassLoader);
        }
        return ClassLoader.getSystemClassLoader();
    }

    public void setServer(Server server) {
        this.server = server;
    }


    public Server getServer() {
        return server;
    }


    /**
     * Return true if naming is enabled.
     */
    public boolean isUseNaming() {
        return (this.useNaming);
    }


    /**
     * Enables or disables naming support.
     *
     * @param useNaming The new use naming value
     */
    public void setUseNaming(boolean useNaming) {
        this.useNaming = useNaming;
    }

    public void setAwait(boolean b) {
        await = b;
    }

    public boolean isAwait() {
        return await;
    }

    // ------------------------------------------------------ Protected Methods


    /**
     * Process the specified command line arguments, and return
     * <code>true</code> if we should continue processing; otherwise
     * return <code>false</code>.
     *
     * @param args Command line arguments to process
     */
    protected boolean arguments(String args[]) {

        boolean isConfig = false;

        if (args.length < 1) {
            usage();
            return false;
        }

        for (int i = 0; i < args.length; i++) {
            if (isConfig) {
                configFile = args[i];
                isConfig = false;
            } else if (args[i].equals("-config")) {
                isConfig = true;
            } else if (args[i].equals("-nonaming")) {
                setUseNaming(false);
            } else if (args[i].equals("-help")) {
                usage();
                return false;
            } else if (args[i].equals("start")) {
                // NOOP
            } else if (args[i].equals("configtest")) {
                // NOOP
            } else if (args[i].equals("stop")) {
                // NOOP
            } else {
                usage();
                return false;
            }
        }

        return true;
    }


    /**
     * Return a File object representing our configuration file.
     */
    protected File configFile() {

        File file = new File(configFile);
        if (!file.isAbsolute()) {
            file = new File(Bootstrap.getCatalinaBase(), configFile);
        }
        return (file);

    }


    /**
     * tomcat中使用Digester库将server.xml等xml文件转换为java对象,并设置一些列的属性
     * tomcat对digester做了一些修改
     * Create and configure the Digester we will be using for startup.
     */
    protected Digester createStartDigester() {
        long t1=System.currentTimeMillis();
        // 初始化digester对象
        Digester digester = new Digester();
        //指定该文件不用dtd验证文档的合法性,因为没有定义相应的dtd文件来验证
        digester.setValidating(false);
        digester.setRulesValidation(true);
        HashMap<Class<?>, List<String>> fakeAttributes = new HashMap<>();
        ArrayList<String> attrs = new ArrayList<>();
        attrs.add("className");
        fakeAttributes.put(Object.class, attrs);
        //设置需要过滤的属性
        digester.setFakeAttributes(fakeAttributes);
        digester.setUseContextClassLoader(true);
        //下面三条规则用于解析server元素
        // 创建server对象(StandardServer根对象).参数:xml元素名称,对应的类,属性名
        // 如果server有一个名为className的属性,那么classname属性的值必须是实例化的类的名称,可以不写
        // addObjectCreate设计的Rule对象是ObjectCreateRule
        digester.addObjectCreate("Server",
                                 "org.apache.catalina.core.StandardServer",
                                 "className");
        //开始为server对象设置属性,就是在解析到Server标签时,将xml文件中和Server类中同名的属性设置为标签中属性的值
        //这就是基于事件的解析方法,比dom,sax要方便很多.使用Java反射机制使用标准的JavaBean方法设置栈顶对象实例；
        //addSetProperties涉及的rule对象是SetPropertiesRule
        digester.addSetProperties("Server");
        //设置元素之间的关系,一般是父子,将当前对象设置到父元素中,调用父元素(Catalina)的setServer方法设置.并把当前元素压倒栈顶
        //因为在解析之前会把this(Catalina)对象压入栈顶,所以就是把server设置到catalina中
        //addSetNext方法涉及的rule对象是SetNextRule
        digester.addSetNext("Server",
                            "setServer",
                            "org.apache.catalina.Server");
        
        //开始第一级子元素GlobalNamingResources的创建,该元素负责JNDI,参数:元素名,元素对应的类
        digester.addObjectCreate("Server/GlobalNamingResources",
                                 "org.apache.catalina.deploy.NamingResourcesImpl");
        //为当前对象设置属性(类中属性和标签中同名的才会设置)
        digester.addSetProperties("Server/GlobalNamingResources");
        //设置元素之间的关系,调用Server的setGlobalNamingResources方法设置
        digester.addSetNext("Server/GlobalNamingResources",
                            "setGlobalNamingResources",
                            "org.apache.catalina.deploy.NamingResourcesImpl");
        //添加Server的生命周期监听器listener,在配置文件中写明了
        digester.addObjectCreate("Server/Listener",
                                 null, // MUST be specified in the element
                                 "className");
        //addSetProperties方法底层也是调用的addRule方法
        digester.addSetProperties("Server/Listener");
        digester.addSetNext("Server/Listener",
                            "addLifecycleListener",
                            "org.apache.catalina.LifecycleListener");
        //创建service实例对象
        digester.addObjectCreate("Server/Service",
                                 "org.apache.catalina.core.StandardService",
                                 "className");
        digester.addSetProperties("Server/Service");
        digester.addSetNext("Server/Service",
                            "addService",
                            "org.apache.catalina.Service");
        //创建service的生命周期监听对象
        digester.addObjectCreate("Server/Service/Listener",
                                 null, // MUST be specified in the element
                                 "className");
        digester.addSetProperties("Server/Service/Listener");
        digester.addSetNext("Server/Service/Listener",
                            "addLifecycleListener",
                            "org.apache.catalina.LifecycleListener");

        //创建Executor,添加到service
        digester.addObjectCreate("Server/Service/Executor",
                         "org.apache.catalina.core.StandardThreadExecutor",
                         "className");
        digester.addSetProperties("Server/Service/Executor");

        digester.addSetNext("Server/Service/Executor",
                            "addExecutor",
                            "org.apache.catalina.Executor");

        //digester.addRule方法是digester.addObjectCreate方法的底层实现,所以原理相同
        //ConnectorCreateRule是一个rule对象
        //创建connector对象
        digester.addRule("Server/Service/Connector",
                         new ConnectorCreateRule());
        digester.addRule("Server/Service/Connector",
                         new SetAllPropertiesRule(new String[]{"executor"}));
        //将Connector对象设置到Service对象中
        digester.addSetNext("Server/Service/Connector",
                            "addConnector",
                            "org.apache.catalina.connector.Connector");

        //创建connector的生命周期监听对象
        digester.addObjectCreate("Server/Service/Connector/Listener",
                                 null, // MUST be specified in the element
                                 "className");
        digester.addSetProperties("Server/Service/Connector/Listener");
        digester.addSetNext("Server/Service/Connector/Listener",
                            "addLifecycleListener",
                            "org.apache.catalina.LifecycleListener");

        // Add RuleSets for nested elements
        //NamingRuleSet是一个RuleSet对象,和上面的稍微不同
        //添加子元素解析规则
        digester.addRuleSet(new NamingRuleSet("Server/GlobalNamingResources/"));
        digester.addRuleSet(new EngineRuleSet("Server/Service/"));
        digester.addRuleSet(new HostRuleSet("Server/Service/Engine/"));
        digester.addRuleSet(new ContextRuleSet("Server/Service/Engine/Host/"));
        addClusterRuleSet(digester, "Server/Service/Engine/Host/Cluster/");
        digester.addRuleSet(new NamingRuleSet("Server/Service/Engine/Host/Context/"));

        // When the 'engine' is found, set the parentClassLoader.
        digester.addRule("Server/Service/Engine",
                         new SetParentClassLoaderRule(parentClassLoader));
        addClusterRuleSet(digester, "Server/Service/Engine/Cluster/");

        long t2=System.currentTimeMillis();
        if (log.isDebugEnabled()) {
            log.debug("Digester for server.xml created " + ( t2-t1 ));
        }
        return (digester);

    }

    /**
     * Cluster support is optional. The JARs may have been removed.
     */
    private void addClusterRuleSet(Digester digester, String prefix) {
        Class<?> clazz = null;
        Constructor<?> constructor = null;
        try {
            clazz = Class.forName("org.apache.catalina.ha.ClusterRuleSet");
            constructor = clazz.getConstructor(String.class);
            RuleSet ruleSet = (RuleSet) constructor.newInstance(prefix);
            digester.addRuleSet(ruleSet);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("catalina.noCluster",
                        e.getClass().getName() + ": " +  e.getMessage()), e);
            } else if (log.isInfoEnabled()) {
                log.info(sm.getString("catalina.noCluster",
                        e.getClass().getName() + ": " +  e.getMessage()));
            }
        }
    }

    /**
     * Create and configure the Digester we will be using for shutdown.
     */
    protected Digester createStopDigester() {

        // Initialize the digester
        Digester digester = new Digester();
        digester.setUseContextClassLoader(true);

        // Configure the rules we need for shutting down
        digester.addObjectCreate("Server",
                                 "org.apache.catalina.core.StandardServer",
                                 "className");
        digester.addSetProperties("Server");
        digester.addSetNext("Server",
                            "setServer",
                            "org.apache.catalina.Server");

        return (digester);

    }


    public void stopServer() {
        stopServer(null);
    }

    public void stopServer(String[] arguments) {

        if (arguments != null) {
            arguments(arguments);
        }

        Server s = getServer();
        if (s == null) {
            // Create and execute our Digester
            Digester digester = createStopDigester();
            //获取conf.server.xml文件
            File file = configFile();
            try (FileInputStream fis = new FileInputStream(file)) {
                InputSource is =
                    new InputSource(file.toURI().toURL().toString());
                is.setByteStream(fis);
                digester.push(this);
                digester.parse(is);
            } catch (Exception e) {
                log.error("Catalina.stop: ", e);
                System.exit(1);
            }
        } else {
            // Server object already present. Must be running as a service
            try {
                s.stop();
            } catch (LifecycleException e) {
                log.error("Catalina.stop: ", e);
            }
            return;
        }

        // Stop the existing server
        s = getServer();
        if (s.getPort()>0) {
            try (Socket socket = new Socket(s.getAddress(), s.getPort());
                    OutputStream stream = socket.getOutputStream()) {
                String shutdown = s.getShutdown();
                for (int i = 0; i < shutdown.length(); i++) {
                    stream.write(shutdown.charAt(i));
                }
                stream.flush();
            } catch (ConnectException ce) {
                log.error(sm.getString("catalina.stopServer.connectException",
                                       s.getAddress(),
                                       String.valueOf(s.getPort())));
                log.error("Catalina.stop: ", ce);
                System.exit(1);
            } catch (IOException e) {
                log.error("Catalina.stop: ", e);
                System.exit(1);
            }
        } else {
            log.error(sm.getString("catalina.stopServer"));
            System.exit(1);
        }
    }


    /**
     * Start a new server instance.
     */
    public void load() {

        if (loaded) {
            return;
        }
        loaded = true;

        long t1 = System.nanoTime();
        //初始化临时文件夹
        initDirs();

        // 将Catalina的名称设置到Ststem.setProperty中
        initNaming();

        // 将server.xml文件中的内容创建java对象,这是后还没有执行parse方法
        Digester digester = createStartDigester();

        InputSource inputSource = null;
        InputStream inputStream = null;
        File file = null;
        try {
            try {
            	//server.xml文件
                file = configFile();
                inputStream = new FileInputStream(file);
                inputSource = new InputSource(file.toURI().toURL().toString());
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("catalina.configFail", file), e);
                }
            }
            if (inputStream == null) {
                try {
                    inputStream = getClass().getClassLoader()
                        .getResourceAsStream(getConfigFile());
                    inputSource = new InputSource
                        (getClass().getClassLoader()
                         .getResource(getConfigFile()).toString());
                } catch (Exception e) {
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("catalina.configFail",
                                getConfigFile()), e);
                    }
                }
            }

            // This should be included in catalina.jar
            // Alternative: don't bother with xml, just create it manually.
            if (inputStream == null) {
                try {
                    inputStream = getClass().getClassLoader()
                            .getResourceAsStream("server-embed.xml");
                    inputSource = new InputSource
                    (getClass().getClassLoader()
                            .getResource("server-embed.xml").toString());
                } catch (Exception e) {
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("catalina.configFail",
                                "server-embed.xml"), e);
                    }
                }
            }


            if (inputStream == null || inputSource == null) {
                if  (file == null) {
                    log.warn(sm.getString("catalina.configFail",
                            getConfigFile() + "] or [server-embed.xml]"));
                } else {
                    log.warn(sm.getString("catalina.configFail",
                            file.getAbsolutePath()));
                    if (file.exists() && !file.canRead()) {
                        log.warn("Permissions incorrect, read permission is not allowed on the file.");
                    }
                }
                return;
            }

            try {
                inputSource.setByteStream(inputStream);
                //在解析server.xml文件之前,将当前Catalina对象push到栈顶
                digester.push(this);
                //执行解析,将digester和相应的xml文件结合起来
                digester.parse(inputSource);
            } catch (SAXParseException spe) {
                log.warn("Catalina.start using " + getConfigFile() + ": " +
                        spe.getMessage());
                return;
            } catch (Exception e) {
                log.warn("Catalina.start using " + getConfigFile() + ": " , e);
                return;
            }
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
        //server对象设置catalina
        getServer().setCatalina(this);
        //设置目录
        getServer().setCatalinaHome(Bootstrap.getCatalinaHomeFile());
        getServer().setCatalinaBase(Bootstrap.getCatalinaBaseFile());

        // System.err和System.out重定向
        initStreams();

        // Start the new server
        try {
        	//调用StandardServer对象的init方法,init方法是StandardServer祖先LifecycleBase中的方法,类似于模板的设计模式
        	//将所有的组件都进行初始化
            getServer().init();
        } catch (LifecycleException e) {
            if (Boolean.getBoolean("org.apache.catalina.startup.EXIT_ON_INIT_FAILURE")) {
                throw new java.lang.Error(e);
            } else {
                log.error("Catalina.start", e);
            }
        }

        long t2 = System.nanoTime();
        if(log.isInfoEnabled()) {
            log.info("Initialization processed in " + ((t2 - t1) / 1000000) + " ms");
        }
    }


    /*
     * Load using arguments
     */
    public void load(String args[]) {

        try {
        	//先处理命令行参数
            if (arguments(args)) {
            	//启动
                load();
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }


    /**
     * Start a new server instance.
     */
    public void start() {

    	//保证服务启动前加载过server.xml文件
        if (getServer() == null) {
            load();
        }

        if (getServer() == null) {
            log.fatal("Cannot start server. Server instance is not configured.");
            return;
        }

        long t1 = System.nanoTime();

        // Start the new server
        try {
        	//同样这里会设计到StandardServer祖先LifecycleBase中的start方法,使得所有组件都start
            getServer().start();
        } catch (LifecycleException e) {
            log.fatal(sm.getString("catalina.serverStartFail"), e);
            try {
                getServer().destroy();
            } catch (LifecycleException e1) {
                log.debug("destroy() failed for failed Server ", e1);
            }
            return;
        }

        long t2 = System.nanoTime();
        if(log.isInfoEnabled()) {
            log.info("Server startup in " + ((t2 - t1) / 1000000) + " ms");
        }

        // 是否注册关闭钩子
        if (useShutdownHook) {
            if (shutdownHook == null) {
            	//初始化容器关闭钩子
                shutdownHook = new CatalinaShutdownHook();
            }
            //将关闭钩子添加到runntime中
            Runtime.getRuntime().addShutdownHook(shutdownHook);

            // If JULI is being used, disable JULI's shutdown hook since
            // shutdown hooks run in parallel and log messages may be lost
            // if JULI's hook completes before the CatalinaShutdownHook()
            LogManager logManager = LogManager.getLogManager();
            if (logManager instanceof ClassLoaderLogManager) {
                ((ClassLoaderLogManager) logManager).setUseShutdownHook(
                        false);
            }
        }
        //一直等待关闭命令
        if (await) {
        	//在standardServer中创建一个socket监听相应的端口,监听tomcat是否关闭,会一直循环监听
            await();
            //关闭tomcat
            stop();
        }
    }


    /**
     * Stop an existing server instance.
     */
    public void stop() {

        try {
            // Remove the ShutdownHook first so that server.stop()
            // doesn't get invoked twice
            if (useShutdownHook) {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);

                // If JULI is being used, re-enable JULI's shutdown to ensure
                // log messages are not lost
                LogManager logManager = LogManager.getLogManager();
                if (logManager instanceof ClassLoaderLogManager) {
                    ((ClassLoaderLogManager) logManager).setUseShutdownHook(
                            true);
                }
            }
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            // This will fail on JDK 1.2. Ignoring, as Tomcat can run
            // fine without the shutdown hook.
        }

        // Shut down the server
        try {
            Server s = getServer();
            LifecycleState state = s.getState();
            if (LifecycleState.STOPPING_PREP.compareTo(state) <= 0
                    && LifecycleState.DESTROYED.compareTo(state) >= 0) {
                // Nothing to do. stop() was already called
            } else {
                s.stop();
                s.destroy();
            }
        } catch (LifecycleException e) {
            log.error("Catalina.stop", e);
        }

    }


    /**
     * Await and shutdown.
     */
    public void await() {
        getServer().await();
    }


    /**
     * Print usage information for this application.
     */
    protected void usage() {
        System.out.println
            ("usage: java org.apache.catalina.startup.Catalina"
             + " [ -config {pathname} ]"
             + " [ -nonaming ] "
             + " { -help | start | stop }");
    }


    protected void initDirs() {
        String temp = System.getProperty("java.io.tmpdir");
        if (temp == null || (!(new File(temp)).isDirectory())) {
            log.error(sm.getString("embedded.notmp", temp));
        }
    }


    protected void initStreams() {
        // Replace System.out and System.err with a custom PrintStream
        System.setOut(new SystemLogHandler(System.out));
        System.setErr(new SystemLogHandler(System.err));
    }


    protected void initNaming() {
        // Setting additional variables
        if (!useNaming) {
            log.info( "Catalina naming disabled");
            System.setProperty("catalina.useNaming", "false");
        } else {
            System.setProperty("catalina.useNaming", "true");
            String value = "org.apache.naming";
            String oldValue =
                System.getProperty(javax.naming.Context.URL_PKG_PREFIXES);
            if (oldValue != null) {
                value = value + ":" + oldValue;
            }
            System.setProperty(javax.naming.Context.URL_PKG_PREFIXES, value);
            if( log.isDebugEnabled() ) {
                log.debug("Setting naming prefix=" + value);
            }
            value = System.getProperty
                (javax.naming.Context.INITIAL_CONTEXT_FACTORY);
            if (value == null) {
                System.setProperty
                    (javax.naming.Context.INITIAL_CONTEXT_FACTORY,
                     "org.apache.naming.java.javaURLContextFactory");
            } else {
                log.debug( "INITIAL_CONTEXT_FACTORY already set " + value );
            }
        }
    }


    /**
     * Set the security package access/protection.
     */
    protected void setSecurityProtection(){
        SecurityConfig securityConfig = SecurityConfig.newInstance();
        securityConfig.setPackageDefinition();
        securityConfig.setPackageAccess();
    }


    // --------------------------------------- CatalinaShutdownHook Inner Class

    // XXX Should be moved to embedded !
    /**
     * tomcat中的关闭钩子
     * Shutdown hook which will perform a clean shutdown of Catalina if needed.
     */
    protected class CatalinaShutdownHook extends Thread {

        @Override
        public void run() {
            try {
                if (getServer() != null) {
                	//关闭容器
                    Catalina.this.stop();
                }
            } catch (Throwable ex) {
                ExceptionUtils.handleThrowable(ex);
                log.error(sm.getString("catalina.shutdownHookFail"), ex);
            } finally {
                // If JULI is used, shut JULI down *after* the server shuts down
                // so log messages aren't lost
                LogManager logManager = LogManager.getLogManager();
                if (logManager instanceof ClassLoaderLogManager) {
                    ((ClassLoaderLogManager) logManager).shutdown();
                }
            }
        }
    }


    private static final org.apache.juli.logging.Log log=
        org.apache.juli.logging.LogFactory.getLog( Catalina.class );

}


// ------------------------------------------------------------ Private Classes


/**
 * Rule that sets the parent class loader for the top object on the stack,
 * which must be a <code>Container</code>.
 */

final class SetParentClassLoaderRule extends Rule {

    public SetParentClassLoaderRule(ClassLoader parentClassLoader) {

        this.parentClassLoader = parentClassLoader;

    }

    ClassLoader parentClassLoader = null;

    @Override
    public void begin(String namespace, String name, Attributes attributes)
        throws Exception {

        if (digester.getLogger().isDebugEnabled()) {
            digester.getLogger().debug("Setting parent class loader");
        }

        Container top = (Container) digester.peek();
        top.setParentClassLoader(parentClassLoader);

    }


}
