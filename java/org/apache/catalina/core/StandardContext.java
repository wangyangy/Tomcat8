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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.EventListener;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Stack;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.management.ListenerNotFoundException;
import javax.management.MBeanNotificationInfo;
import javax.management.Notification;
import javax.management.NotificationBroadcasterSupport;
import javax.management.NotificationEmitter;
import javax.management.NotificationFilter;
import javax.management.NotificationListener;
import javax.naming.NamingException;
import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.FilterRegistration;
import javax.servlet.RequestDispatcher;
import javax.servlet.Servlet;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextAttributeListener;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;
import javax.servlet.ServletRegistration.Dynamic;
import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestAttributeListener;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.ServletSecurityElement;
import javax.servlet.SessionCookieConfig;
import javax.servlet.SessionTrackingMode;
import javax.servlet.descriptor.JspConfigDescriptor;
import javax.servlet.http.HttpSessionAttributeListener;
import javax.servlet.http.HttpSessionIdListener;
import javax.servlet.http.HttpSessionListener;

import org.apache.catalina.Authenticator;
import org.apache.catalina.Container;
import org.apache.catalina.ContainerListener;
import org.apache.catalina.Context;
import org.apache.catalina.CredentialHandler;
import org.apache.catalina.Globals;
import org.apache.catalina.InstanceListener;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Loader;
import org.apache.catalina.Manager;
import org.apache.catalina.Pipeline;
import org.apache.catalina.Realm;
import org.apache.catalina.ThreadBindingListener;
import org.apache.catalina.Valve;
import org.apache.catalina.WebResource;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.Wrapper;
import org.apache.catalina.deploy.NamingResourcesImpl;
import org.apache.catalina.loader.WebappLoader;
import org.apache.catalina.session.StandardManager;
import org.apache.catalina.util.CharsetMapper;
import org.apache.catalina.util.ContextName;
import org.apache.catalina.util.ExtensionValidator;
import org.apache.catalina.util.URLEncoder;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.naming.ContextBindings;
import org.apache.tomcat.InstanceManager;
import org.apache.tomcat.JarScanner;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.IntrospectionUtils;
import org.apache.tomcat.util.buf.UDecoder;
import org.apache.tomcat.util.descriptor.XmlIdentifiers;
import org.apache.tomcat.util.descriptor.web.ApplicationParameter;
import org.apache.tomcat.util.descriptor.web.ErrorPage;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.apache.tomcat.util.descriptor.web.Injectable;
import org.apache.tomcat.util.descriptor.web.InjectionTarget;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.MessageDestination;
import org.apache.tomcat.util.descriptor.web.MessageDestinationRef;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.apache.tomcat.util.http.CookieProcessor;
import org.apache.tomcat.util.http.LegacyCookieProcessor;
import org.apache.tomcat.util.scan.StandardJarScanner;
import org.apache.tomcat.util.security.PrivilegedGetTccl;
import org.apache.tomcat.util.security.PrivilegedSetTccl;

/**
 * Context对应着web应用
 * Standard implementation of the <b>Context</b> interface.  Each
 * child container must be a Wrapper implementation to process the
 * requests directed to a particular servlet.
 */
@SuppressWarnings("deprecation")
public class StandardContext extends ContainerBase
        implements Context, NotificationEmitter {

    private static final Log log = LogFactory.getLog(StandardContext.class);


    public StandardContext() {
        super();
        //管道设置基础阀,基础阀会处理收到的每个http请求
        pipeline.setBasic(new StandardContextValve());
        //用于JMX广播的
        broadcaster = new NotificationBroadcasterSupport();
        // Set defaults
        if (!Globals.STRICT_SERVLET_COMPLIANCE) {
            resourceOnlyServlets.add("jsp");
        }
    }

    /**
     * Allow multipart/form-data requests to be parsed even when the target servlet doesn't specify 
     */
    protected boolean allowCasualMultipartParsing = false;

    private boolean swallowAbortedUploads = true;

    private String altDDName = null;

    private InstanceManager instanceManager = null;

    private boolean antiResourceLocking = false;

    private String applicationListeners[] = new String[0];

    private final Object applicationListenersLock = new Object();

    private final Set<Object> noPluggabilityListeners = new HashSet<>();

    private List<Object> applicationEventListenersList = new CopyOnWriteArrayList<>();

    private Object applicationLifecycleListenersObjects[] =
        new Object[0];

    private Map<ServletContainerInitializer,Set<Class<?>>> initializers =
        new LinkedHashMap<>();

    private ApplicationParameter applicationParameters[] =
        new ApplicationParameter[0];

    private final Object applicationParametersLock = new Object();

    private NotificationBroadcasterSupport broadcaster = null;

    private CharsetMapper charsetMapper = null;

    private String charsetMapperClass =
      "org.apache.catalina.util.CharsetMapper";

    private URL configFile = null;

    private boolean configured = false;

    //安全认证相关的类
    private volatile SecurityConstraint constraints[] =
            new SecurityConstraint[0];

    private final Object constraintsLock = new Object();

    //ServletContext的具体实现类
    protected ApplicationContext context = null;

    private NoPluggabilityServletContext noPluggabilityServletContext = null;

    //是否启用cookie
    private boolean cookies = true;

    private boolean crossContext = false;

    //编码过的路径
    private String encodedPath = null;

    //没有进行编码的路径
    private String path = null;

    private boolean delegate = false;

    private boolean denyUncoveredHttpMethods;

    private String displayName = null;

    private String defaultContextXml;

    private String defaultWebXml;

    private boolean distributable = false;

    private String docBase = null;

    private HashMap<String, ErrorPage> exceptionPages = new HashMap<>();

    //过滤器配置
    private HashMap<String, ApplicationFilterConfig> filterConfigs =
            new HashMap<>();

    //过滤器集
    private HashMap<String, FilterDef> filterDefs = new HashMap<>();

    private final ContextFilterMaps filterMaps = new ContextFilterMaps();

    private boolean ignoreAnnotations = false;

    private String instanceListeners[] = new String[0];

    private final Object instanceListenersLock = new Object();

    //载入器
    private Loader loader = null;
    private final ReadWriteLock loaderLock = new ReentrantReadWriteLock();

    private LoginConfig loginConfig = null;
    
    //会话管理器
    protected Manager manager = null;
    private final ReadWriteLock managerLock = new ReentrantReadWriteLock();

    private NamingContextListener namingContextListener = null;
    //命名资源
    private NamingResourcesImpl namingResources = null;

    private HashMap<String, MessageDestination> messageDestinations =
        new HashMap<>();
    //元数据映射
    private HashMap<String, String> mimeMappings = new HashMap<>();

    //参数
    private final ConcurrentMap<String, String> parameters = new ConcurrentHashMap<>();

    private volatile boolean paused = false;

    private String publicId = null;

    //该属性表示应用程序是否启用了重载的功能,如果启用了该功能,当web.xml文件改变或者任何一个class文件改变,应用程序会重载
    private boolean reloadable = false;

    private boolean unpackWAR = true;

    private boolean copyXML = false;

    private boolean override = false;

    private String originalDocBase = null;

    private boolean privileged = false;

    private boolean replaceWelcomeFiles = false;

    private HashMap<String, String> roleMappings = new HashMap<>();

    private String securityRoles[] = new String[0];

    private final Object securityRolesLock = new Object();

    private HashMap<String, String> servletMappings = new HashMap<>();

    private final Object servletMappingsLock = new Object();

    //session失效时间默认是30分钟
    private int sessionTimeout = 30;

    private AtomicLong sequenceNumber = new AtomicLong(0);

    private HashMap<Integer, ErrorPage> statusPages = new HashMap<>();

    private boolean swallowOutput = false;

    private long unloadDelay = 2000;

    private String watchedResources[] = new String[0];

    private final Object watchedResourcesLock = new Object();

    private String welcomeFiles[] = new String[0];

    private final Object welcomeFilesLock = new Object();

    private String wrapperLifecycles[] = new String[0];

    private final Object wrapperLifecyclesLock = new Object();

    private String wrapperListeners[] = new String[0];

    private final Object wrapperListenersLock = new Object();

    private String workDir = null;

    private String wrapperClassName = StandardWrapper.class.getName();
    private Class<?> wrapperClass = null;

    private boolean useNaming = true;

    private String namingContextName = null;

    private WebResourceRoot resources;
    private final ReadWriteLock resourcesLock = new ReentrantReadWriteLock();

    private long startupTime;
    private long startTime;
    private long tldScanTime;

    private String j2EEApplication="none";
    private String j2EEServer="none";

    private boolean webXmlValidation = Globals.STRICT_SERVLET_COMPLIANCE;

    private boolean webXmlNamespaceAware = Globals.STRICT_SERVLET_COMPLIANCE;

    private boolean xmlBlockExternal = true;

    private boolean tldValidation = Globals.STRICT_SERVLET_COMPLIANCE;

    private String sessionCookieName;

    private boolean useHttpOnly = true;

    private String sessionCookieDomain;

    private String sessionCookiePath;

    private boolean sessionCookiePathUsesTrailingSlash = false;
    //Jar扫描器
    private JarScanner jarScanner = null;

    private boolean clearReferencesRmiTargets = true;

    @Deprecated
    private boolean clearReferencesStatic = false;

    private boolean clearReferencesStopThreads = false;

    private boolean clearReferencesStopTimerThreads = false;

    private boolean clearReferencesHttpClientKeepAliveThread = true;

    private boolean renewThreadsWhenStoppingContext = true;

    private boolean logEffectiveWebXml = false;

    private int effectiveMajorVersion = 3;

    private int effectiveMinorVersion = 0;

    private JspConfigDescriptor jspConfigDescriptor = null;

    private Set<String> resourceOnlyServlets = new HashSet<>();

    private String webappVersion = "";

    private boolean addWebinfClassesResources = false;

    private boolean fireRequestListenersOnForwards = false;

    private Set<Servlet> createdServlets = new HashSet<>();

    private boolean preemptiveAuthentication = false;

    private boolean sendRedirectBody = false;

    private boolean jndiExceptionOnFailedWrite = true;

    private Map<String, String> postConstructMethods = new HashMap<>();
    private Map<String, String> preDestroyMethods = new HashMap<>();

    private String containerSciFilter;

    private Boolean failCtxIfServletStartFails;

    protected static final ThreadBindingListener DEFAULT_NAMING_LISTENER = (new ThreadBindingListener() {
        @Override
        public void bind() {}
        @Override
        public void unbind() {}
    });
    protected ThreadBindingListener threadBindingListener = DEFAULT_NAMING_LISTENER;

    private final Object namingToken = new Object();

    private CookieProcessor cookieProcessor;

    private boolean validateClientProvidedNewSessionId = true;

    private boolean mapperContextRootRedirectEnabled = true;

    private boolean mapperDirectoryRedirectEnabled = false;

    private boolean useRelativeRedirects = !Globals.STRICT_SERVLET_COMPLIANCE;

    private boolean dispatchersUseEncodedPaths = true;
    // ----------------------------------------------------- Context Properties

    @Override
    public void setDispatchersUseEncodedPaths(boolean dispatchersUseEncodedPaths) {
        this.dispatchersUseEncodedPaths = dispatchersUseEncodedPaths;
    }

    @Override
    public boolean getDispatchersUseEncodedPaths() {
        return dispatchersUseEncodedPaths;
    }


    @Override
    public void setUseRelativeRedirects(boolean useRelativeRedirects) {
        this.useRelativeRedirects = useRelativeRedirects;
    }

    @Override
    public boolean getUseRelativeRedirects() {
        return useRelativeRedirects;
    }

    @Override
    public void setMapperContextRootRedirectEnabled(boolean mapperContextRootRedirectEnabled) {
        this.mapperContextRootRedirectEnabled = mapperContextRootRedirectEnabled;
    }

    @Override
    public boolean getMapperContextRootRedirectEnabled() {
        return mapperContextRootRedirectEnabled;
    }

    @Override
    public void setMapperDirectoryRedirectEnabled(boolean mapperDirectoryRedirectEnabled) {
        this.mapperDirectoryRedirectEnabled = mapperDirectoryRedirectEnabled;
    }

    @Override
    public boolean getMapperDirectoryRedirectEnabled() {
        return mapperDirectoryRedirectEnabled;
    }

    @Override
    public void setValidateClientProvidedNewSessionId(boolean validateClientProvidedNewSessionId) {
        this.validateClientProvidedNewSessionId = validateClientProvidedNewSessionId;
    }

    @Override
    public boolean getValidateClientProvidedNewSessionId() {
        return validateClientProvidedNewSessionId;
    }

    @Override
    public void setCookieProcessor(CookieProcessor cookieProcessor) {
        if (cookieProcessor == null) {
            throw new IllegalArgumentException(
                    sm.getString("standardContext.cookieProcessor.null"));
        }
        this.cookieProcessor = cookieProcessor;
    }

    @Override
    public CookieProcessor getCookieProcessor() {
        return cookieProcessor;
    }

    @Override
    public Object getNamingToken() {
        return namingToken;
    }

    @Override
    public void setContainerSciFilter(String containerSciFilter) {
        this.containerSciFilter = containerSciFilter;
    }

    @Override
    public String getContainerSciFilter() {
        return containerSciFilter;
    }

    @Override
    public boolean getSendRedirectBody() {
        return sendRedirectBody;
    }

    @Override
    public void setSendRedirectBody(boolean sendRedirectBody) {
        this.sendRedirectBody = sendRedirectBody;
    }

    @Override
    public boolean getPreemptiveAuthentication() {
        return preemptiveAuthentication;
    }

    @Override
    public void setPreemptiveAuthentication(boolean preemptiveAuthentication) {
        this.preemptiveAuthentication = preemptiveAuthentication;
    }

    @Override
    public void setFireRequestListenersOnForwards(boolean enable) {
        fireRequestListenersOnForwards = enable;
    }

    @Override
    public boolean getFireRequestListenersOnForwards() {
        return fireRequestListenersOnForwards;
    }

    @Override
    public void setAddWebinfClassesResources(
            boolean addWebinfClassesResources) {
        this.addWebinfClassesResources = addWebinfClassesResources;
    }

    @Override
    public boolean getAddWebinfClassesResources() {
        return addWebinfClassesResources;
    }

    @Override
    public void setWebappVersion(String webappVersion) {
        if (null == webappVersion) {
            this.webappVersion = "";
        } else {
            this.webappVersion = webappVersion;
        }
    }

    @Override
    public String getWebappVersion() {
        return webappVersion;
    }

    @Override
    public String getBaseName() {
        return new ContextName(path, webappVersion).getBaseName();
    }

    @Override
    public String getResourceOnlyServlets() {
        StringBuilder result = new StringBuilder();
        boolean first = true;
        for (String servletName : resourceOnlyServlets) {
            if (first) {
                first = false;
            } else {
                result.append(',');
            }
            result.append(servletName);
        }
        return result.toString();
    }

    @Override
    public void setResourceOnlyServlets(String resourceOnlyServlets) {
        this.resourceOnlyServlets.clear();
        if (resourceOnlyServlets == null) {
            return;
        }
        for (String servletName : resourceOnlyServlets.split(",")) {
            servletName = servletName.trim();
            if (servletName.length()>0) {
                this.resourceOnlyServlets.add(servletName);
            }
        }
    }

    @Override
    public boolean isResourceOnlyServlet(String servletName) {
        return resourceOnlyServlets.contains(servletName);
    }

    @Override
    public int getEffectiveMajorVersion() {
        return effectiveMajorVersion;
    }

    @Override
    public void setEffectiveMajorVersion(int effectiveMajorVersion) {
        this.effectiveMajorVersion = effectiveMajorVersion;
    }

    @Override
    public int getEffectiveMinorVersion() {
        return effectiveMinorVersion;
    }

    @Override
    public void setEffectiveMinorVersion(int effectiveMinorVersion) {
        this.effectiveMinorVersion = effectiveMinorVersion;
    }

    @Override
    public void setLogEffectiveWebXml(boolean logEffectiveWebXml) {
        this.logEffectiveWebXml = logEffectiveWebXml;
    }

    @Override
    public boolean getLogEffectiveWebXml() {
        return logEffectiveWebXml;
    }

    @Override
    public Authenticator getAuthenticator() {
        if (this instanceof Authenticator)
            return (Authenticator) this;

        Pipeline pipeline = getPipeline();
        if (pipeline != null) {
            Valve basic = pipeline.getBasic();
            if ((basic != null) && (basic instanceof Authenticator))
                return (Authenticator) basic;
            Valve valves[] = pipeline.getValves();
            for (int i = 0; i < valves.length; i++) {
                if (valves[i] instanceof Authenticator)
                    return (Authenticator) valves[i];
            }
        }
        return null;
    }

    @Override
    public JarScanner getJarScanner() {
        if (jarScanner == null) {
            jarScanner = new StandardJarScanner();
        }
        return jarScanner;
    }

    @Override
    public void setJarScanner(JarScanner jarScanner) {
        this.jarScanner = jarScanner;
    }

    @Override
    public InstanceManager getInstanceManager() {
       return instanceManager;
    }

    @Override
    public void setInstanceManager(InstanceManager instanceManager) {
       this.instanceManager = instanceManager;
    }

    @Override
    public String getEncodedPath() {
        return encodedPath;
    }

    @Override
    public void setAllowCasualMultipartParsing(
            boolean allowCasualMultipartParsing) {
        this.allowCasualMultipartParsing = allowCasualMultipartParsing;
    }

    @Override
    public boolean getAllowCasualMultipartParsing() {
        return this.allowCasualMultipartParsing;
    }

    @Override
    public void setSwallowAbortedUploads(boolean swallowAbortedUploads) {
        this.swallowAbortedUploads = swallowAbortedUploads;
    }

    @Override
    public boolean getSwallowAbortedUploads() {
        return this.swallowAbortedUploads;
    }

    @Override
    public void addServletContainerInitializer(
            ServletContainerInitializer sci, Set<Class<?>> classes) {
        initializers.put(sci, classes);
    }

    public boolean getDelegate() {
        return (this.delegate);
    }

    public void setDelegate(boolean delegate) {
        boolean oldDelegate = this.delegate;
        this.delegate = delegate;
        support.firePropertyChange("delegate", oldDelegate,
                                   this.delegate);
    }

    public boolean isUseNaming() {

        return (useNaming);

    }

    public void setUseNaming(boolean useNaming) {
        this.useNaming = useNaming;
    }


    @Override
    public Object[] getApplicationEventListeners() {
        return applicationEventListenersList.toArray();
    }

    @Override
    public void setApplicationEventListeners(Object listeners[]) {
        applicationEventListenersList.clear();
        if (listeners != null && listeners.length > 0) {
            applicationEventListenersList.addAll(Arrays.asList(listeners));
        }
    }

    public void addApplicationEventListener(Object listener) {
        applicationEventListenersList.add(listener);
    }

    @Override
    public Object[] getApplicationLifecycleListeners() {
        return (applicationLifecycleListenersObjects);
    }

    @Override
    public void setApplicationLifecycleListeners(Object listeners[]) {
        applicationLifecycleListenersObjects = listeners;
    }

    public void addApplicationLifecycleListener(Object listener) {
        int len = applicationLifecycleListenersObjects.length;
        Object[] newListeners = Arrays.copyOf(
                applicationLifecycleListenersObjects, len + 1);
        newListeners[len] = listener;
        applicationLifecycleListenersObjects = newListeners;
    }

    public boolean getAntiResourceLocking() {
        return (this.antiResourceLocking);
    }

    public void setAntiResourceLocking(boolean antiResourceLocking) {
        boolean oldAntiResourceLocking = this.antiResourceLocking;
        this.antiResourceLocking = antiResourceLocking;
        support.firePropertyChange("antiResourceLocking",
                                   oldAntiResourceLocking,
                                   this.antiResourceLocking);
    }

    public CharsetMapper getCharsetMapper() {
        if (this.charsetMapper == null) {
            try {
                Class<?> clazz = Class.forName(charsetMapperClass);
                this.charsetMapper = (CharsetMapper) clazz.getDeclaredConstructor().newInstance();
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                this.charsetMapper = new CharsetMapper();
            }
        }
        return (this.charsetMapper);
    }

    public void setCharsetMapper(CharsetMapper mapper) {
        CharsetMapper oldCharsetMapper = this.charsetMapper;
        this.charsetMapper = mapper;
        if( mapper != null )
            this.charsetMapperClass= mapper.getClass().getName();
        support.firePropertyChange("charsetMapper", oldCharsetMapper,
                                   this.charsetMapper);
    }

    @Override
    public String getCharset(Locale locale) {
        return getCharsetMapper().getCharset(locale);
    }

    @Override
    public URL getConfigFile() {
        return this.configFile;
    }

    @Override
    public void setConfigFile(URL configFile) {
        this.configFile = configFile;
    }

    @Override
    public boolean getConfigured() {
        return this.configured;
    }

    @Override
    public void setConfigured(boolean configured) {
        boolean oldConfigured = this.configured;
        this.configured = configured;
        support.firePropertyChange("configured",
                                   oldConfigured,
                                   this.configured);
    }

    @Override
    public boolean getCookies() {
        return this.cookies;
    }


    @Override
    public void setCookies(boolean cookies) {
        boolean oldCookies = this.cookies;
        this.cookies = cookies;
        support.firePropertyChange("cookies",
                                   oldCookies,
                                   this.cookies);
    }

    @Override
    public String getSessionCookieName() {
        return sessionCookieName;
    }

    @Override
    public void setSessionCookieName(String sessionCookieName) {
        String oldSessionCookieName = this.sessionCookieName;
        this.sessionCookieName = sessionCookieName;
        support.firePropertyChange("sessionCookieName",
                oldSessionCookieName, sessionCookieName);
    }

    @Override
    public boolean getUseHttpOnly() {
        return useHttpOnly;
    }

    @Override
    public void setUseHttpOnly(boolean useHttpOnly) {
        boolean oldUseHttpOnly = this.useHttpOnly;
        this.useHttpOnly = useHttpOnly;
        support.firePropertyChange("useHttpOnly",
                oldUseHttpOnly,
                this.useHttpOnly);
    }

    @Override
    public String getSessionCookieDomain() {
        return sessionCookieDomain;
    }

    @Override
    public void setSessionCookieDomain(String sessionCookieDomain) {
        String oldSessionCookieDomain = this.sessionCookieDomain;
        this.sessionCookieDomain = sessionCookieDomain;
        support.firePropertyChange("sessionCookieDomain",
                oldSessionCookieDomain, sessionCookieDomain);
    }

    @Override
    public String getSessionCookiePath() {
        return sessionCookiePath;
    }

    @Override
    public void setSessionCookiePath(String sessionCookiePath) {
        String oldSessionCookiePath = this.sessionCookiePath;
        this.sessionCookiePath = sessionCookiePath;
        support.firePropertyChange("sessionCookiePath",
                oldSessionCookiePath, sessionCookiePath);
    }

    @Override
    public boolean getSessionCookiePathUsesTrailingSlash() {
        return sessionCookiePathUsesTrailingSlash;
    }

    @Override
    public void setSessionCookiePathUsesTrailingSlash(
            boolean sessionCookiePathUsesTrailingSlash) {
        this.sessionCookiePathUsesTrailingSlash =
            sessionCookiePathUsesTrailingSlash;
    }

    @Override
    public boolean getCrossContext() {
        return this.crossContext;
    }

    @Override
    public void setCrossContext(boolean crossContext) {
        boolean oldCrossContext = this.crossContext;
        this.crossContext = crossContext;
        support.firePropertyChange("crossContext",
                                   oldCrossContext,
                                   this.crossContext);
    }

    public String getDefaultContextXml() {
        return defaultContextXml;
    }

    public void setDefaultContextXml(String defaultContextXml) {
        this.defaultContextXml = defaultContextXml;
    }

    public String getDefaultWebXml() {
        return defaultWebXml;
    }

    public void setDefaultWebXml(String defaultWebXml) {
        this.defaultWebXml = defaultWebXml;
    }

    public long getStartupTime() {
        return startupTime;
    }

    public void setStartupTime(long startupTime) {
        this.startupTime = startupTime;
    }

    public long getTldScanTime() {
        return tldScanTime;
    }

    public void setTldScanTime(long tldScanTime) {
        this.tldScanTime = tldScanTime;
    }

    @Override
    public boolean getDenyUncoveredHttpMethods() {
        return denyUncoveredHttpMethods;
    }

    @Override
    public void setDenyUncoveredHttpMethods(boolean denyUncoveredHttpMethods) {
        this.denyUncoveredHttpMethods = denyUncoveredHttpMethods;
    }

    @Override
    public String getDisplayName() {
        return (this.displayName);
    }

    @Override
    public String getAltDDName(){
        return altDDName;
    }

    @Override
    public void setAltDDName(String altDDName) {
        this.altDDName = altDDName;
        if (context != null) {
            context.setAttribute(Globals.ALT_DD_ATTR,altDDName);
        }
    }

    @Override
    public void setDisplayName(String displayName) {
        String oldDisplayName = this.displayName;
        this.displayName = displayName;
        support.firePropertyChange("displayName", oldDisplayName,
                                   this.displayName);
    }

    @Override
    public boolean getDistributable() {
        return (this.distributable);
    }

    @Override
    public void setDistributable(boolean distributable) {
        boolean oldDistributable = this.distributable;
        this.distributable = distributable;
        support.firePropertyChange("distributable",
                                   oldDistributable,
                                   this.distributable);
    }

    @Override
    public String getDocBase() {

        return (this.docBase);

    }

    @Override
    public void setDocBase(String docBase) {

        this.docBase = docBase;

    }

    public String getJ2EEApplication() {
        return j2EEApplication;
    }

    public void setJ2EEApplication(String j2EEApplication) {
        this.j2EEApplication = j2EEApplication;
    }

    public String getJ2EEServer() {
        return j2EEServer;
    }

    public void setJ2EEServer(String j2EEServer) {
        this.j2EEServer = j2EEServer;
    }

    @Override
    public Loader getLoader() {
        Lock readLock = loaderLock.readLock();
        readLock.lock();
        try {
            return loader;
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public void setLoader(Loader loader) {
        Lock writeLock = loaderLock.writeLock();
        writeLock.lock();
        Loader oldLoader = null;
        try {
            // Change components if necessary
            oldLoader = this.loader;
            if (oldLoader == loader)
                return;
            this.loader = loader;
            // Stop the old component if necessary
            if (getState().isAvailable() && (oldLoader != null) &&
                (oldLoader instanceof Lifecycle)) {
                try {
                    ((Lifecycle) oldLoader).stop();
                } catch (LifecycleException e) {
                    log.error("StandardContext.setLoader: stop: ", e);
                }
            }
            // Start the new component if necessary
            if (loader != null)
                loader.setContext(this);
            if (getState().isAvailable() && (loader != null) &&
                (loader instanceof Lifecycle)) {
                try {
                    ((Lifecycle) loader).start();
                } catch (LifecycleException e) {
                    log.error("StandardContext.setLoader: start: ", e);
                }
            }
        } finally {
            writeLock.unlock();
        }
        // Report this property change to interested listeners
        support.firePropertyChange("loader", oldLoader, loader);
    }

    @Override
    public Manager getManager() {
        Lock readLock = managerLock.readLock();
        readLock.lock();
        try {
            return manager;
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public void setManager(Manager manager) {
        Lock writeLock = managerLock.writeLock();
        writeLock.lock();
        Manager oldManager = null;
        try {
            // Change components if necessary
            oldManager = this.manager;
            if (oldManager == manager)
                return;
            this.manager = manager;

            // Stop the old component if necessary
            if (oldManager instanceof Lifecycle) {
                try {
                    ((Lifecycle) oldManager).stop();
                    ((Lifecycle) oldManager).destroy();
                } catch (LifecycleException e) {
                    log.error("StandardContext.setManager: stop-destroy: ", e);
                }
            }
            // Start the new component if necessary
            if (manager != null) {
                manager.setContext(this);
            }
            if (getState().isAvailable() && manager instanceof Lifecycle) {
                try {
                    ((Lifecycle) manager).start();
                } catch (LifecycleException e) {
                    log.error("StandardContext.setManager: start: ", e);
                }
            }
        } finally {
            writeLock.unlock();
        }
        // Report this property change to interested listeners
        support.firePropertyChange("manager", oldManager, manager);
    }

    @Override
    public boolean getIgnoreAnnotations() {
        return this.ignoreAnnotations;
    }

    @Override
    public void setIgnoreAnnotations(boolean ignoreAnnotations) {
        boolean oldIgnoreAnnotations = this.ignoreAnnotations;
        this.ignoreAnnotations = ignoreAnnotations;
        support.firePropertyChange("ignoreAnnotations", oldIgnoreAnnotations,
                this.ignoreAnnotations);
    }

    @Override
    public LoginConfig getLoginConfig() {
        return (this.loginConfig);
    }

    @Override
    public void setLoginConfig(LoginConfig config) {
        // Validate the incoming property value
        if (config == null)
            throw new IllegalArgumentException
                (sm.getString("standardContext.loginConfig.required"));
        String loginPage = config.getLoginPage();
        if ((loginPage != null) && !loginPage.startsWith("/")) {
            if (isServlet22()) {
                if(log.isDebugEnabled())
                    log.debug(sm.getString("standardContext.loginConfig.loginWarning",
                                 loginPage));
                config.setLoginPage("/" + loginPage);
            } else {
                throw new IllegalArgumentException
                    (sm.getString("standardContext.loginConfig.loginPage",
                                  loginPage));
            }
        }
        String errorPage = config.getErrorPage();
        if ((errorPage != null) && !errorPage.startsWith("/")) {
            if (isServlet22()) {
                if(log.isDebugEnabled())
                    log.debug(sm.getString("standardContext.loginConfig.errorWarning",
                                 errorPage));
                config.setErrorPage("/" + errorPage);
            } else {
                throw new IllegalArgumentException
                    (sm.getString("standardContext.loginConfig.errorPage",
                                  errorPage));
            }
        }

        // Process the property setting change
        LoginConfig oldLoginConfig = this.loginConfig;
        this.loginConfig = config;
        support.firePropertyChange("loginConfig",
                                   oldLoginConfig, this.loginConfig);

    }

    @Override
    public NamingResourcesImpl getNamingResources() {
        if (namingResources == null) {
            setNamingResources(new NamingResourcesImpl());
        }
        return (namingResources);
    }

    @Override
    public void setNamingResources(NamingResourcesImpl namingResources) {
        // Process the property setting change
        NamingResourcesImpl oldNamingResources = this.namingResources;
        this.namingResources = namingResources;
        if (namingResources != null) {
            namingResources.setContainer(this);
        }
        support.firePropertyChange("namingResources",
                                   oldNamingResources, this.namingResources);
        if (getState() == LifecycleState.NEW ||
                getState() == LifecycleState.INITIALIZING ||
                getState() == LifecycleState.INITIALIZED) {
            return;
        }

        if (oldNamingResources != null) {
            try {
                oldNamingResources.stop();
                oldNamingResources.destroy();
            } catch (LifecycleException e) {
                log.warn("standardContext.namingResource.destroy.fail", e);
            }
        }
        if (namingResources != null) {
            try {
                namingResources.init();
                namingResources.start();
            } catch (LifecycleException e) {
                log.warn("standardContext.namingResource.init.fail", e);
            }
        }
    }

    @Override
    public String getPath() {
        return (path);
    }

    @Override
    public void setPath(String path) {
        boolean invalid = false;
        if (path == null || path.equals("/")) {
            invalid = true;
            this.path = "";
        } else if ("".equals(path) || path.startsWith("/")) {
            this.path = path;
        } else {
            invalid = true;
            this.path = "/" + path;
        }
        if (this.path.endsWith("/")) {
            invalid = true;
            this.path = this.path.substring(0, this.path.length() - 1);
        }
        if (invalid) {
            log.warn(sm.getString(
                    "standardContext.pathInvalid", path, this.path));
        }
        encodedPath = URLEncoder.DEFAULT.encode(this.path, "UTF-8");
        if (getName() == null) {
            setName(this.path);
        }
    }

    @Override
    public String getPublicId() {
        return (this.publicId);
    }

    @Override
    public void setPublicId(String publicId) {
        if (log.isDebugEnabled())
            log.debug("Setting deployment descriptor public ID to '" +
                publicId + "'");
        String oldPublicId = this.publicId;
        this.publicId = publicId;
        support.firePropertyChange("publicId", oldPublicId, publicId);
    }

    @Override
    public boolean getReloadable() {
        return (this.reloadable);
    }

    @Override
    public boolean getOverride() {
        return (this.override);
    }

    public String getOriginalDocBase() {
        return (this.originalDocBase);
    }

    public void setOriginalDocBase(String docBase) {
        this.originalDocBase = docBase;
    }

    @Override
    public ClassLoader getParentClassLoader() {
        if (parentClassLoader != null)
            return (parentClassLoader);
        if (getPrivileged()) {
            return this.getClass().getClassLoader();
        } else if (parent != null) {
            return (parent.getParentClassLoader());
        }
        return (ClassLoader.getSystemClassLoader());
    }

    @Override
    public boolean getPrivileged() {
        return (this.privileged);
    }

    @Override
    public void setPrivileged(boolean privileged) {
        boolean oldPrivileged = this.privileged;
        this.privileged = privileged;
        support.firePropertyChange("privileged",
                                   oldPrivileged,
                                   this.privileged);
    }

    @Override
    public void setReloadable(boolean reloadable) {
        boolean oldReloadable = this.reloadable;
        this.reloadable = reloadable;
        support.firePropertyChange("reloadable",
                                   oldReloadable,
                                   this.reloadable);
    }

    @Override
    public void setOverride(boolean override) {
        boolean oldOverride = this.override;
        this.override = override;
        support.firePropertyChange("override",
                                   oldOverride,
                                   this.override);
    }

    public void setReplaceWelcomeFiles(boolean replaceWelcomeFiles) {
        boolean oldReplaceWelcomeFiles = this.replaceWelcomeFiles;
        this.replaceWelcomeFiles = replaceWelcomeFiles;
        support.firePropertyChange("replaceWelcomeFiles",
                                   oldReplaceWelcomeFiles,
                                   this.replaceWelcomeFiles);

    }

    @Override
    public ServletContext getServletContext() {
        if (context == null) {
        	//ServletContext的标准实现类ApplicationContext
            context = new ApplicationContext(this);
            if (altDDName != null)
                context.setAttribute(Globals.ALT_DD_ATTR,altDDName);
        }
        return (context.getFacade());
    }

    @Override
    public int getSessionTimeout() {
        return (this.sessionTimeout);
    }

    @Override
    public void setSessionTimeout(int timeout) {
        int oldSessionTimeout = this.sessionTimeout;
        this.sessionTimeout = (timeout == 0) ? -1 : timeout;
        support.firePropertyChange("sessionTimeout",
                                   oldSessionTimeout,
                                   this.sessionTimeout);
    }

    @Override
    public boolean getSwallowOutput() {
        return (this.swallowOutput);
    }

    @Override
    public void setSwallowOutput(boolean swallowOutput) {
        boolean oldSwallowOutput = this.swallowOutput;
        this.swallowOutput = swallowOutput;
        support.firePropertyChange("swallowOutput",
                                   oldSwallowOutput,
                                   this.swallowOutput);
    }

    public long getUnloadDelay() {
        return (this.unloadDelay);
    }

    public void setUnloadDelay(long unloadDelay) {
        long oldUnloadDelay = this.unloadDelay;
        this.unloadDelay = unloadDelay;
        support.firePropertyChange("unloadDelay",
                                   Long.valueOf(oldUnloadDelay),
                                   Long.valueOf(this.unloadDelay));
    }

    public boolean getUnpackWAR() {
        return (unpackWAR);
    }

    public void setUnpackWAR(boolean unpackWAR) {
        this.unpackWAR = unpackWAR;
    }

    public boolean getCopyXML() {
        return copyXML;
    }

    public void setCopyXML(boolean copyXML) {
        this.copyXML = copyXML;
    }

    @Override
    public String getWrapperClass() {
        return (this.wrapperClassName);
    }

    @Override
    public void setWrapperClass(String wrapperClassName) {
        this.wrapperClassName = wrapperClassName;
        try {
            wrapperClass = Class.forName(wrapperClassName);
            if (!StandardWrapper.class.isAssignableFrom(wrapperClass)) {
                throw new IllegalArgumentException(
                    sm.getString("standardContext.invalidWrapperClass",
                                 wrapperClassName));
            }
        } catch (ClassNotFoundException cnfe) {
            throw new IllegalArgumentException(cnfe.getMessage());
        }
    }

    @Override
    public WebResourceRoot getResources() {
        Lock readLock = resourcesLock.readLock();
        readLock.lock();
        try {
            return resources;
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public void setResources(WebResourceRoot resources) {
        Lock writeLock = resourcesLock.writeLock();
        writeLock.lock();
        WebResourceRoot oldResources = null;
        try {
            if (getState().isAvailable()) {
                throw new IllegalStateException
                    (sm.getString("standardContext.resourcesStart"));
            }
            oldResources = this.resources;
            if (oldResources == resources)
                return;
            this.resources = resources;
            if (oldResources != null) {
                oldResources.setContext(null);
            }
            if (resources != null) {
                resources.setContext(this);
            }
            support.firePropertyChange("resources", oldResources,
                    resources);
        } finally {
            writeLock.unlock();
        }
    }


    @Override
    public JspConfigDescriptor getJspConfigDescriptor() {
        return jspConfigDescriptor;
    }

    @Override
    public void setJspConfigDescriptor(JspConfigDescriptor descriptor) {
        this.jspConfigDescriptor = descriptor;
    }

    @Override
    public ThreadBindingListener getThreadBindingListener() {
        return threadBindingListener;
    }

    @Override
    public void setThreadBindingListener(ThreadBindingListener threadBindingListener) {
        this.threadBindingListener = threadBindingListener;
    }

    // ------------------------------------------------------ Public Properties

    public boolean getJndiExceptionOnFailedWrite() {
        return jndiExceptionOnFailedWrite;
    }

    public void setJndiExceptionOnFailedWrite(
            boolean jndiExceptionOnFailedWrite) {
        this.jndiExceptionOnFailedWrite = jndiExceptionOnFailedWrite;
    }


    public String getCharsetMapperClass() {
        return (this.charsetMapperClass);
    }

    public void setCharsetMapperClass(String mapper) {
        String oldCharsetMapperClass = this.charsetMapperClass;
        this.charsetMapperClass = mapper;
        support.firePropertyChange("charsetMapperClass",
                                   oldCharsetMapperClass,
                                   this.charsetMapperClass);
    }

    public String getWorkPath() {
        if (getWorkDir() == null) {
            return null;
        }
        File workDir = new File(getWorkDir());
        if (!workDir.isAbsolute()) {
            try {
                workDir = new File(getCatalinaBase().getCanonicalFile(),
                        getWorkDir());
            } catch (IOException e) {
                log.warn(sm.getString("standardContext.workPath", getName()),
                        e);
            }
        }
        return workDir.getAbsolutePath();
    }

    public String getWorkDir() {
        return (this.workDir);
    }

    public void setWorkDir(String workDir) {
        this.workDir = workDir;
        if (getState().isAvailable()) {
            postWorkDirectory();
        }
    }

    public boolean getClearReferencesRmiTargets() {
        return this.clearReferencesRmiTargets;
    }

    public void setClearReferencesRmiTargets(boolean clearReferencesRmiTargets) {
        boolean oldClearReferencesRmiTargets = this.clearReferencesRmiTargets;
        this.clearReferencesRmiTargets = clearReferencesRmiTargets;
        support.firePropertyChange("clearReferencesRmiTargets",
                oldClearReferencesRmiTargets, this.clearReferencesRmiTargets);
    }

    @Deprecated
    public boolean getClearReferencesStatic() {
        return (this.clearReferencesStatic);
    }

    @Deprecated
    public void setClearReferencesStatic(boolean clearReferencesStatic) {
        boolean oldClearReferencesStatic = this.clearReferencesStatic;
        this.clearReferencesStatic = clearReferencesStatic;
        support.firePropertyChange("clearReferencesStatic",
                                   oldClearReferencesStatic,
                                   this.clearReferencesStatic);
    }

    public boolean getClearReferencesStopThreads() {
        return (this.clearReferencesStopThreads);
    }

    public void setClearReferencesStopThreads(
            boolean clearReferencesStopThreads) {
        boolean oldClearReferencesStopThreads = this.clearReferencesStopThreads;
        this.clearReferencesStopThreads = clearReferencesStopThreads;
        support.firePropertyChange("clearReferencesStopThreads",
                                   oldClearReferencesStopThreads,
                                   this.clearReferencesStopThreads);
    }

    public boolean getClearReferencesStopTimerThreads() {
        return (this.clearReferencesStopTimerThreads);
    }

    public void setClearReferencesStopTimerThreads(
            boolean clearReferencesStopTimerThreads) {
        boolean oldClearReferencesStopTimerThreads =
            this.clearReferencesStopTimerThreads;
        this.clearReferencesStopTimerThreads = clearReferencesStopTimerThreads;
        support.firePropertyChange("clearReferencesStopTimerThreads",
                                   oldClearReferencesStopTimerThreads,
                                   this.clearReferencesStopTimerThreads);
    }

    public boolean getClearReferencesHttpClientKeepAliveThread() {
        return (this.clearReferencesHttpClientKeepAliveThread);
    }

    public void setClearReferencesHttpClientKeepAliveThread(
            boolean clearReferencesHttpClientKeepAliveThread) {
        this.clearReferencesHttpClientKeepAliveThread =
            clearReferencesHttpClientKeepAliveThread;
    }

    public boolean getRenewThreadsWhenStoppingContext() {
        return this.renewThreadsWhenStoppingContext;
    }

    public void setRenewThreadsWhenStoppingContext(
            boolean renewThreadsWhenStoppingContext) {
        boolean oldRenewThreadsWhenStoppingContext =
                this.renewThreadsWhenStoppingContext;
        this.renewThreadsWhenStoppingContext = renewThreadsWhenStoppingContext;
        support.firePropertyChange("renewThreadsWhenStoppingContext",
                oldRenewThreadsWhenStoppingContext,
                this.renewThreadsWhenStoppingContext);
    }

    public Boolean getFailCtxIfServletStartFails() {
        return failCtxIfServletStartFails;
    }

    public void setFailCtxIfServletStartFails(
            Boolean failCtxIfServletStartFails) {
        Boolean oldFailCtxIfServletStartFails = this.failCtxIfServletStartFails;
        this.failCtxIfServletStartFails = failCtxIfServletStartFails;
        support.firePropertyChange("failCtxIfServletStartFails",
                oldFailCtxIfServletStartFails,
                failCtxIfServletStartFails);
    }

    protected boolean getComputedFailCtxIfServletStartFails() {
        if(failCtxIfServletStartFails != null) {
            return failCtxIfServletStartFails.booleanValue();
        }
        //else look at Host config
        if(getParent() instanceof StandardHost) {
            return ((StandardHost)getParent()).isFailCtxIfServletStartFails();
        }
        //else
        return false;
    }

    // -------------------------------------------------------- Context Methods

    @Override
    public void addApplicationListener(String listener) {
        synchronized (applicationListenersLock) {
            String results[] = new String[applicationListeners.length + 1];
            for (int i = 0; i < applicationListeners.length; i++) {
                if (listener.equals(applicationListeners[i])) {
                    log.info(sm.getString("standardContext.duplicateListener",listener));
                    return;
                }
                results[i] = applicationListeners[i];
            }
            results[applicationListeners.length] = listener;
            applicationListeners = results;
        }
        fireContainerEvent("addApplicationListener", listener);
    }

    @Override
    public void addApplicationParameter(ApplicationParameter parameter) {
        synchronized (applicationParametersLock) {
            String newName = parameter.getName();
            for (ApplicationParameter p : applicationParameters) {
                if (newName.equals(p.getName()) && !p.getOverride())
                    return;
            }
            ApplicationParameter results[] = Arrays.copyOf(
                    applicationParameters, applicationParameters.length + 1);
            results[applicationParameters.length] = parameter;
            applicationParameters = results;
        }
        fireContainerEvent("addApplicationParameter", parameter);
    }

    @Override
    public void addChild(Container child) {
        Wrapper oldJspServlet = null;
        if (!(child instanceof Wrapper)) {
            throw new IllegalArgumentException
                (sm.getString("standardContext.notWrapper"));
        }
        boolean isJspServlet = "jsp".equals(child.getName());
        if (isJspServlet) {
            oldJspServlet = (Wrapper) findChild("jsp");
            if (oldJspServlet != null) {
                removeChild(oldJspServlet);
            }
        }
        super.addChild(child);
        if (isJspServlet && oldJspServlet != null) {
            String[] jspMappings = oldJspServlet.findMappings();
            for (int i=0; jspMappings!=null && i<jspMappings.length; i++) {
                addServletMappingDecoded(jspMappings[i], child.getName());
            }
        }
    }

    @Override
    public void addConstraint(SecurityConstraint constraint) {
        SecurityCollection collections[] = constraint.findCollections();
        for (int i = 0; i < collections.length; i++) {
            String patterns[] = collections[i].findPatterns();
            for (int j = 0; j < patterns.length; j++) {
                patterns[j] = adjustURLPattern(patterns[j]);
                if (!validateURLPattern(patterns[j]))
                    throw new IllegalArgumentException
                        (sm.getString
                         ("standardContext.securityConstraint.pattern",
                          patterns[j]));
            }
            if (collections[i].findMethods().length > 0 &&
                    collections[i].findOmittedMethods().length > 0) {
                throw new IllegalArgumentException(sm.getString(
                        "standardContext.securityConstraint.mixHttpMethod"));
            }
        }

        synchronized (constraintsLock) {
            SecurityConstraint results[] =
                new SecurityConstraint[constraints.length + 1];
            for (int i = 0; i < constraints.length; i++)
                results[i] = constraints[i];
            results[constraints.length] = constraint;
            constraints = results;
        }

    }

    @Override
    public void addErrorPage(ErrorPage errorPage) {
        // Validate the input parameters
        if (errorPage == null)
            throw new IllegalArgumentException
                (sm.getString("standardContext.errorPage.required"));
        String location = errorPage.getLocation();
        if ((location != null) && !location.startsWith("/")) {
            if (isServlet22()) {
                if(log.isDebugEnabled())
                    log.debug(sm.getString("standardContext.errorPage.warning",
                                 location));
                errorPage.setLocation("/" + location);
            } else {
                throw new IllegalArgumentException
                    (sm.getString("standardContext.errorPage.error",
                                  location));
            }
        }

        // Add the specified error page to our internal collections
        String exceptionType = errorPage.getExceptionType();
        if (exceptionType != null) {
            synchronized (exceptionPages) {
                exceptionPages.put(exceptionType, errorPage);
            }
        } else {
            synchronized (statusPages) {
                statusPages.put(Integer.valueOf(errorPage.getErrorCode()),
                                errorPage);
            }
        }
        fireContainerEvent("addErrorPage", errorPage);
    }

    @Override
    public void addFilterDef(FilterDef filterDef) {
        synchronized (filterDefs) {
            filterDefs.put(filterDef.getFilterName(), filterDef);
        }
        fireContainerEvent("addFilterDef", filterDef);
    }

    @Override
    public void addFilterMap(FilterMap filterMap) {
        validateFilterMap(filterMap);
        // Add this filter mapping to our registered set
        filterMaps.add(filterMap);
        fireContainerEvent("addFilterMap", filterMap);
    }

    @Override
    public void addFilterMapBefore(FilterMap filterMap) {
        validateFilterMap(filterMap);
        // Add this filter mapping to our registered set
        filterMaps.addBefore(filterMap);
        fireContainerEvent("addFilterMap", filterMap);
    }

    private void validateFilterMap(FilterMap filterMap) {
        // Validate the proposed filter mapping
        String filterName = filterMap.getFilterName();
        String[] servletNames = filterMap.getServletNames();
        String[] urlPatterns = filterMap.getURLPatterns();
        if (findFilterDef(filterName) == null)
            throw new IllegalArgumentException
                (sm.getString("standardContext.filterMap.name", filterName));

        if (!filterMap.getMatchAllServletNames() &&
            !filterMap.getMatchAllUrlPatterns() &&
            (servletNames.length == 0) && (urlPatterns.length == 0))
            throw new IllegalArgumentException
                (sm.getString("standardContext.filterMap.either"));
        // FIXME: Older spec revisions may still check this
        /*
        if ((servletNames.length != 0) && (urlPatterns.length != 0))
            throw new IllegalArgumentException
                (sm.getString("standardContext.filterMap.either"));
        */
        for (int i = 0; i < urlPatterns.length; i++) {
            if (!validateURLPattern(urlPatterns[i])) {
                throw new IllegalArgumentException
                    (sm.getString("standardContext.filterMap.pattern",
                            urlPatterns[i]));
            }
        }
    }

    @Deprecated
    @Override
    public void addInstanceListener(String listener) {
        synchronized (instanceListenersLock) {
            String results[] =new String[instanceListeners.length + 1];
            for (int i = 0; i < instanceListeners.length; i++)
                results[i] = instanceListeners[i];
            results[instanceListeners.length] = listener;
            instanceListeners = results;
        }
        fireContainerEvent("addInstanceListener", listener);
    }

    @Override
    public void addLocaleEncodingMappingParameter(String locale, String encoding){
        getCharsetMapper().addCharsetMappingFromDeploymentDescriptor(locale, encoding);
    }

    public void addMessageDestination(MessageDestination md) {
        synchronized (messageDestinations) {
            messageDestinations.put(md.getName(), md);
        }
        fireContainerEvent("addMessageDestination", md.getName());
    }

    public void addMessageDestinationRef(MessageDestinationRef mdr) {
        namingResources.addMessageDestinationRef(mdr);
        fireContainerEvent("addMessageDestinationRef", mdr.getName());
    }

    @Override
    public void addMimeMapping(String extension, String mimeType) {
        synchronized (mimeMappings) {
            mimeMappings.put(extension.toLowerCase(Locale.ENGLISH), mimeType);
        }
        fireContainerEvent("addMimeMapping", extension);
    }

    @Override
    public void addParameter(String name, String value) {
        // Validate the proposed context initialization parameter
        if ((name == null) || (value == null)) {
            throw new IllegalArgumentException
                (sm.getString("standardContext.parameter.required"));
        }
        // Add this parameter to our defined set if not already present
        String oldValue = parameters.putIfAbsent(name, value);
        if (oldValue != null) {
            throw new IllegalArgumentException(
                    sm.getString("standardContext.parameter.duplicate", name));
        }
        fireContainerEvent("addParameter", name);
    }

    @Override
    public void addRoleMapping(String role, String link) {
        synchronized (roleMappings) {
            roleMappings.put(role, link);
        }
        fireContainerEvent("addRoleMapping", role);
    }

    @Override
    public void addSecurityRole(String role) {
        synchronized (securityRolesLock) {
            String results[] =new String[securityRoles.length + 1];
            for (int i = 0; i < securityRoles.length; i++)
                results[i] = securityRoles[i];
            results[securityRoles.length] = role;
            securityRoles = results;
        }
        fireContainerEvent("addSecurityRole", role);
    }

    @Override
    @Deprecated
    public void addServletMapping(String pattern, String name) {
        addServletMapping(pattern, name, false);
    }

    @Override
    @Deprecated
    public void addServletMapping(String pattern, String name, boolean jspWildCard) {
        addServletMappingDecoded(UDecoder.URLDecode(pattern, "UTF-8"), name, false);
    }

    @Override
    public void addServletMappingDecoded(String pattern, String name) {
        addServletMappingDecoded(pattern, name, false);
    }

    @Override
    public void addServletMappingDecoded(String pattern, String name,
                                  boolean jspWildCard) {
        // Validate the proposed mapping
        if (findChild(name) == null)
            throw new IllegalArgumentException
                (sm.getString("standardContext.servletMap.name", name));
        String adjustedPattern = adjustURLPattern(pattern);
        if (!validateURLPattern(adjustedPattern))
            throw new IllegalArgumentException
                (sm.getString("standardContext.servletMap.pattern", adjustedPattern));

        // Add this mapping to our registered set
        synchronized (servletMappingsLock) {
            String name2 = servletMappings.get(adjustedPattern);
            if (name2 != null) {
                // Don't allow more than one servlet on the same pattern
                Wrapper wrapper = (Wrapper) findChild(name2);
                wrapper.removeMapping(adjustedPattern);
            }
            servletMappings.put(adjustedPattern, name);
        }
        Wrapper wrapper = (Wrapper) findChild(name);
        wrapper.addMapping(adjustedPattern);
        fireContainerEvent("addServletMapping", adjustedPattern);
    }

    @Override
    public void addWatchedResource(String name) {
        synchronized (watchedResourcesLock) {
            String results[] = new String[watchedResources.length + 1];
            for (int i = 0; i < watchedResources.length; i++)
                results[i] = watchedResources[i];
            results[watchedResources.length] = name;
            watchedResources = results;
        }
        fireContainerEvent("addWatchedResource", name);
    }


    @Override
    public void addWelcomeFile(String name) {
        synchronized (welcomeFilesLock) {
            // Welcome files from the application deployment descriptor
            // completely replace those from the default conf/web.xml file
            if (replaceWelcomeFiles) {
                fireContainerEvent(CLEAR_WELCOME_FILES_EVENT, null);
                welcomeFiles = new String[0];
                setReplaceWelcomeFiles(false);
            }
            String results[] =new String[welcomeFiles.length + 1];
            for (int i = 0; i < welcomeFiles.length; i++)
                results[i] = welcomeFiles[i];
            results[welcomeFiles.length] = name;
            welcomeFiles = results;
        }
        if(this.getState().equals(LifecycleState.STARTED))
            fireContainerEvent(ADD_WELCOME_FILE_EVENT, name);
    }


    @Override
    public void addWrapperLifecycle(String listener) {
        synchronized (wrapperLifecyclesLock) {
            String results[] =new String[wrapperLifecycles.length + 1];
            for (int i = 0; i < wrapperLifecycles.length; i++)
                results[i] = wrapperLifecycles[i];
            results[wrapperLifecycles.length] = listener;
            wrapperLifecycles = results;
        }
        fireContainerEvent("addWrapperLifecycle", listener);
    }

    @Override
    public void addWrapperListener(String listener) {
        synchronized (wrapperListenersLock) {
            String results[] =new String[wrapperListeners.length + 1];
            for (int i = 0; i < wrapperListeners.length; i++)
                results[i] = wrapperListeners[i];
            results[wrapperListeners.length] = listener;
            wrapperListeners = results;
        }
        fireContainerEvent("addWrapperListener", listener);
    }

    @Override
    public Wrapper createWrapper() {
        Wrapper wrapper = null;
        if (wrapperClass != null) {
            try {
                wrapper = (Wrapper) wrapperClass.getDeclaredConstructor().newInstance();
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.error("createWrapper", t);
                return null;
            }
        } else {
            wrapper = new StandardWrapper();
        }
        synchronized (instanceListenersLock) {
            for (int i = 0; i < instanceListeners.length; i++) {
                try {
                    Class<?> clazz = Class.forName(instanceListeners[i]);
                    InstanceListener listener =
                            (InstanceListener) clazz.getConstructor().newInstance();
                    wrapper.addInstanceListener(listener);
                } catch (Throwable t) {
                    ExceptionUtils.handleThrowable(t);
                    log.error("createWrapper", t);
                    return (null);
                }
            }
        }

        synchronized (wrapperLifecyclesLock) {
            for (int i = 0; i < wrapperLifecycles.length; i++) {
                try {
                    Class<?> clazz = Class.forName(wrapperLifecycles[i]);
                    LifecycleListener listener =
                        (LifecycleListener) clazz.getDeclaredConstructor().newInstance();
                    wrapper.addLifecycleListener(listener);
                } catch (Throwable t) {
                    ExceptionUtils.handleThrowable(t);
                    log.error("createWrapper", t);
                    return null;
                }
            }
        }

        synchronized (wrapperListenersLock) {
            for (int i = 0; i < wrapperListeners.length; i++) {
                try {
                    Class<?> clazz = Class.forName(wrapperListeners[i]);
                    ContainerListener listener =
                            (ContainerListener) clazz.getDeclaredConstructor().newInstance();
                    wrapper.addContainerListener(listener);
                } catch (Throwable t) {
                    ExceptionUtils.handleThrowable(t);
                    log.error("createWrapper", t);
                    return null;
                }
            }
        }

        return wrapper;
    }

    @Override
    public String[] findApplicationListeners() {
        return applicationListeners;
    }

    @Override
    public ApplicationParameter[] findApplicationParameters() {
        synchronized (applicationParametersLock) {
            return (applicationParameters);
        }
    }

    @Override
    public SecurityConstraint[] findConstraints() {
        return (constraints);
    }

    @Override
    public ErrorPage findErrorPage(int errorCode) {
        return statusPages.get(Integer.valueOf(errorCode));
    }

    @Override
    public ErrorPage findErrorPage(String exceptionType) {
        synchronized (exceptionPages) {
            return (exceptionPages.get(exceptionType));
        }
    }

    @Override
    public ErrorPage[] findErrorPages() {
        synchronized(exceptionPages) {
            synchronized(statusPages) {
                ErrorPage results1[] = new ErrorPage[exceptionPages.size()];
                results1 = exceptionPages.values().toArray(results1);
                ErrorPage results2[] = new ErrorPage[statusPages.size()];
                results2 = statusPages.values().toArray(results2);
                ErrorPage results[] =
                    new ErrorPage[results1.length + results2.length];
                for (int i = 0; i < results1.length; i++)
                    results[i] = results1[i];
                for (int i = results1.length; i < results.length; i++)
                    results[i] = results2[i - results1.length];
                return (results);
            }
        }
    }

    @Override
    public FilterDef findFilterDef(String filterName) {
        synchronized (filterDefs) {
            return (filterDefs.get(filterName));
        }
    }

    @Override
    public FilterDef[] findFilterDefs() {
        synchronized (filterDefs) {
            FilterDef results[] = new FilterDef[filterDefs.size()];
            return (filterDefs.values().toArray(results));
        }
    }

    @Override
    public FilterMap[] findFilterMaps() {
        return filterMaps.asArray();
    }

    @Deprecated
    @Override
    public String[] findInstanceListeners() {
        synchronized (instanceListenersLock) {
            return (instanceListeners);
        }
    }

    public MessageDestination findMessageDestination(String name) {
        synchronized (messageDestinations) {
            return (messageDestinations.get(name));
        }
    }

    public MessageDestination[] findMessageDestinations() {
        synchronized (messageDestinations) {
            MessageDestination results[] =
                new MessageDestination[messageDestinations.size()];
            return (messageDestinations.values().toArray(results));
        }
    }

    public MessageDestinationRef findMessageDestinationRef(String name) {
        return namingResources.findMessageDestinationRef(name);
    }

    public MessageDestinationRef[] findMessageDestinationRefs() {
        return namingResources.findMessageDestinationRefs();
    }

    @Override
    public String findMimeMapping(String extension) {
        return (mimeMappings.get(extension.toLowerCase(Locale.ENGLISH)));
    }

    @Override
    public String[] findMimeMappings() {
        synchronized (mimeMappings) {
            String results[] = new String[mimeMappings.size()];
            return
                (mimeMappings.keySet().toArray(results));
        }
    }

    @Override
    public String findParameter(String name) {
        return parameters.get(name);
    }

    @Override
    public String[] findParameters() {
        List<String> parameterNames = new ArrayList<>(parameters.size());
        parameterNames.addAll(parameters.keySet());
        return parameterNames.toArray(new String[parameterNames.size()]);
    }

    @Override
    public String findRoleMapping(String role) {
        String realRole = null;
        synchronized (roleMappings) {
            realRole = roleMappings.get(role);
        }
        if (realRole != null)
            return (realRole);
        else
            return (role);
    }

    @Override
    public boolean findSecurityRole(String role) {
        synchronized (securityRolesLock) {
            for (int i = 0; i < securityRoles.length; i++) {
                if (role.equals(securityRoles[i]))
                    return (true);
            }
        }
        return (false);
    }

    @Override
    public String[] findSecurityRoles() {
        synchronized (securityRolesLock) {
            return (securityRoles);
        }
    }

    @Override
    public String findServletMapping(String pattern) {
        synchronized (servletMappingsLock) {
            return (servletMappings.get(pattern));
        }
    }

    @Override
    public String[] findServletMappings() {
        synchronized (servletMappingsLock) {
            String results[] = new String[servletMappings.size()];
            return
               (servletMappings.keySet().toArray(results));
        }
    }

    @Override
    public String findStatusPage(int status) {
        ErrorPage errorPage = statusPages.get(Integer.valueOf(status));
        if (errorPage!=null) {
            return errorPage.getLocation();
        }
        return null;
    }

    @Override
    public int[] findStatusPages() {
        synchronized (statusPages) {
            int results[] = new int[statusPages.size()];
            Iterator<Integer> elements = statusPages.keySet().iterator();
            int i = 0;
            while (elements.hasNext())
                results[i++] = elements.next().intValue();
            return (results);
        }
    }

    @Override
    public boolean findWelcomeFile(String name) {
        synchronized (welcomeFilesLock) {
            for (int i = 0; i < welcomeFiles.length; i++) {
                if (name.equals(welcomeFiles[i]))
                    return (true);
            }
        }
        return (false);
    }

    @Override
    public String[] findWatchedResources() {
        synchronized (watchedResourcesLock) {
            return watchedResources;
        }
    }

    @Override
    public String[] findWelcomeFiles() {
        synchronized (welcomeFilesLock) {
            return (welcomeFiles);
        }
    }

    @Override
    public String[] findWrapperLifecycles() {
        synchronized (wrapperLifecyclesLock) {
            return (wrapperLifecycles);
        }
    }

    @Override
    public String[] findWrapperListeners() {
        synchronized (wrapperListenersLock) {
            return (wrapperListeners);
        }
    }

    @Override
    public synchronized void reload() {
        // Validate our current component state
        if (!getState().isAvailable())
            throw new IllegalStateException
                (sm.getString("standardContext.notStarted", getName()));

        if(log.isInfoEnabled())
            log.info(sm.getString("standardContext.reloadingStarted",
                    getName()));
        // Stop accepting requests temporarily.
        setPaused(true);
        try {
            stop();
        } catch (LifecycleException e) {
            log.error(
                sm.getString("standardContext.stoppingContext", getName()), e);
        }
        try {
            start();
        } catch (LifecycleException e) {
            log.error(
                sm.getString("standardContext.startingContext", getName()), e);
        }
        setPaused(false);
        if(log.isInfoEnabled())
            log.info(sm.getString("standardContext.reloadingCompleted",
                    getName()));

    }

    @Override
    public void removeApplicationListener(String listener) {
        synchronized (applicationListenersLock) {
            // Make sure this listener is currently present
            int n = -1;
            for (int i = 0; i < applicationListeners.length; i++) {
                if (applicationListeners[i].equals(listener)) {
                    n = i;
                    break;
                }
            }
            if (n < 0)
                return;
            // Remove the specified listener
            int j = 0;
            String results[] = new String[applicationListeners.length - 1];
            for (int i = 0; i < applicationListeners.length; i++) {
                if (i != n)
                    results[j++] = applicationListeners[i];
            }
            applicationListeners = results;
        }
        // Inform interested listeners
        fireContainerEvent("removeApplicationListener", listener);
    }

    @Override
    public void removeApplicationParameter(String name) {
        synchronized (applicationParametersLock) {
            // Make sure this parameter is currently present
            int n = -1;
            for (int i = 0; i < applicationParameters.length; i++) {
                if (name.equals(applicationParameters[i].getName())) {
                    n = i;
                    break;
                }
            }
            if (n < 0)
                return;
            // Remove the specified parameter
            int j = 0;
            ApplicationParameter results[] =
                new ApplicationParameter[applicationParameters.length - 1];
            for (int i = 0; i < applicationParameters.length; i++) {
                if (i != n)
                    results[j++] = applicationParameters[i];
            }
            applicationParameters = results;

        }
        // Inform interested listeners
        fireContainerEvent("removeApplicationParameter", name);
    }

    @Override
    public void removeChild(Container child) {
        if (!(child instanceof Wrapper)) {
            throw new IllegalArgumentException
                (sm.getString("standardContext.notWrapper"));
        }
        super.removeChild(child);
    }

    @Override
    public void removeConstraint(SecurityConstraint constraint) {
        synchronized (constraintsLock) {
            // Make sure this constraint is currently present
            int n = -1;
            for (int i = 0; i < constraints.length; i++) {
                if (constraints[i].equals(constraint)) {
                    n = i;
                    break;
                }
            }
            if (n < 0)
                return;

            // Remove the specified constraint
            int j = 0;
            SecurityConstraint results[] =
                new SecurityConstraint[constraints.length - 1];
            for (int i = 0; i < constraints.length; i++) {
                if (i != n)
                    results[j++] = constraints[i];
            }
            constraints = results;
        }
        // Inform interested listeners
        fireContainerEvent("removeConstraint", constraint);
    }

    @Override
    public void removeErrorPage(ErrorPage errorPage) {
        String exceptionType = errorPage.getExceptionType();
        if (exceptionType != null) {
            synchronized (exceptionPages) {
                exceptionPages.remove(exceptionType);
            }
        } else {
            synchronized (statusPages) {
                statusPages.remove(Integer.valueOf(errorPage.getErrorCode()));
            }
        }
        fireContainerEvent("removeErrorPage", errorPage);
    }

    @Override
    public void removeFilterDef(FilterDef filterDef) {
        synchronized (filterDefs) {
            filterDefs.remove(filterDef.getFilterName());
        }
        fireContainerEvent("removeFilterDef", filterDef);
    }

    @Override
    public void removeFilterMap(FilterMap filterMap) {
        filterMaps.remove(filterMap);
        // Inform interested listeners
        fireContainerEvent("removeFilterMap", filterMap);
    }

    @Deprecated
    @Override
    public void removeInstanceListener(String listener) {
        synchronized (instanceListenersLock) {
            // Make sure this listener is currently present
            int n = -1;
            for (int i = 0; i < instanceListeners.length; i++) {
                if (instanceListeners[i].equals(listener)) {
                    n = i;
                    break;
                }
            }
            if (n < 0)
                return;
            // Remove the specified listener
            int j = 0;
            String results[] = new String[instanceListeners.length - 1];
            for (int i = 0; i < instanceListeners.length; i++) {
                if (i != n)
                    results[j++] = instanceListeners[i];
            }
            instanceListeners = results;
        }
        // Inform interested listeners
        fireContainerEvent("removeInstanceListener", listener);
    }

    public void removeMessageDestination(String name) {
        synchronized (messageDestinations) {
            messageDestinations.remove(name);
        }
        fireContainerEvent("removeMessageDestination", name);
    }

    public void removeMessageDestinationRef(String name) {
        namingResources.removeMessageDestinationRef(name);
        fireContainerEvent("removeMessageDestinationRef", name);
    }

    @Override
    public void removeMimeMapping(String extension) {
        synchronized (mimeMappings) {
            mimeMappings.remove(extension);
        }
        fireContainerEvent("removeMimeMapping", extension);
    }

    @Override
    public void removeParameter(String name) {
        parameters.remove(name);
        fireContainerEvent("removeParameter", name);
    }

    @Override
    public void removeRoleMapping(String role) {
        synchronized (roleMappings) {
            roleMappings.remove(role);
        }
        fireContainerEvent("removeRoleMapping", role);
    }

    @Override
    public void removeSecurityRole(String role) {
        synchronized (securityRolesLock) {
            // Make sure this security role is currently present
            int n = -1;
            for (int i = 0; i < securityRoles.length; i++) {
                if (role.equals(securityRoles[i])) {
                    n = i;
                    break;
                }
            }
            if (n < 0)
                return;
            // Remove the specified security role
            int j = 0;
            String results[] = new String[securityRoles.length - 1];
            for (int i = 0; i < securityRoles.length; i++) {
                if (i != n)
                    results[j++] = securityRoles[i];
            }
            securityRoles = results;
        }
        // Inform interested listeners
        fireContainerEvent("removeSecurityRole", role);
    }

    @Override
    public void removeServletMapping(String pattern) {
        String name = null;
        synchronized (servletMappingsLock) {
            name = servletMappings.remove(pattern);
        }
        Wrapper wrapper = (Wrapper) findChild(name);
        if( wrapper != null ) {
            wrapper.removeMapping(pattern);
        }
        fireContainerEvent("removeServletMapping", pattern);
    }

    @Override
    public void removeWatchedResource(String name) {
        synchronized (watchedResourcesLock) {
            // Make sure this watched resource is currently present
            int n = -1;
            for (int i = 0; i < watchedResources.length; i++) {
                if (watchedResources[i].equals(name)) {
                    n = i;
                    break;
                }
            }
            if (n < 0)
                return;
            // Remove the specified watched resource
            int j = 0;
            String results[] = new String[watchedResources.length - 1];
            for (int i = 0; i < watchedResources.length; i++) {
                if (i != n)
                    results[j++] = watchedResources[i];
            }
            watchedResources = results;
        }
        fireContainerEvent("removeWatchedResource", name);
    }

    @Override
    public void removeWelcomeFile(String name) {
        synchronized (welcomeFilesLock) {
            // Make sure this welcome file is currently present
            int n = -1;
            for (int i = 0; i < welcomeFiles.length; i++) {
                if (welcomeFiles[i].equals(name)) {
                    n = i;
                    break;
                }
            }
            if (n < 0)
                return;
            // Remove the specified welcome file
            int j = 0;
            String results[] = new String[welcomeFiles.length - 1];
            for (int i = 0; i < welcomeFiles.length; i++) {
                if (i != n)
                    results[j++] = welcomeFiles[i];
            }
            welcomeFiles = results;
        }
        // Inform interested listeners
        if(this.getState().equals(LifecycleState.STARTED))
            fireContainerEvent(REMOVE_WELCOME_FILE_EVENT, name);
    }

    @Override
    public void removeWrapperLifecycle(String listener) {
        synchronized (wrapperLifecyclesLock) {
            // Make sure this lifecycle listener is currently present
            int n = -1;
            for (int i = 0; i < wrapperLifecycles.length; i++) {
                if (wrapperLifecycles[i].equals(listener)) {
                    n = i;
                    break;
                }
            }
            if (n < 0)
                return;
            // Remove the specified lifecycle listener
            int j = 0;
            String results[] = new String[wrapperLifecycles.length - 1];
            for (int i = 0; i < wrapperLifecycles.length; i++) {
                if (i != n)
                    results[j++] = wrapperLifecycles[i];
            }
            wrapperLifecycles = results;
        }
        // Inform interested listeners
        fireContainerEvent("removeWrapperLifecycle", listener);
    }

    @Override
    public void removeWrapperListener(String listener) {
        synchronized (wrapperListenersLock) {
            // Make sure this listener is currently present
            int n = -1;
            for (int i = 0; i < wrapperListeners.length; i++) {
                if (wrapperListeners[i].equals(listener)) {
                    n = i;
                    break;
                }
            }
            if (n < 0)
                return;
            // Remove the specified listener
            int j = 0;
            String results[] = new String[wrapperListeners.length - 1];
            for (int i = 0; i < wrapperListeners.length; i++) {
                if (i != n)
                    results[j++] = wrapperListeners[i];
            }
            wrapperListeners = results;
        }
        // Inform interested listeners
        fireContainerEvent("removeWrapperListener", listener);
    }

    public long getProcessingTime() {
        long result = 0;
        Container[] children = findChildren();
        if (children != null) {
            for( int i=0; i< children.length; i++ ) {
                result += ((StandardWrapper)children[i]).getProcessingTime();
            }
        }
        return result;
    }

    public long getMaxTime() {
        long result = 0;
        long time;
        Container[] children = findChildren();
        if (children != null) {
            for( int i=0; i< children.length; i++ ) {
                time = ((StandardWrapper)children[i]).getMaxTime();
                if (time > result)
                    result = time;
            }
        }
        return result;
    }

    public long getMinTime() {
        long result = -1;
        long time;
        Container[] children = findChildren();
        if (children != null) {
            for( int i=0; i< children.length; i++ ) {
                time = ((StandardWrapper)children[i]).getMinTime();
                if (result < 0 || time < result)
                    result = time;
            }
        }
        return result;
    }

    public int getRequestCount() {
        int result = 0;
        Container[] children = findChildren();
        if (children != null) {
            for( int i=0; i< children.length; i++ ) {
                result += ((StandardWrapper)children[i]).getRequestCount();
            }
        }
        return result;
    }

    public int getErrorCount() {
        int result = 0;
        Container[] children = findChildren();
        if (children != null) {
            for( int i=0; i< children.length; i++ ) {
                result += ((StandardWrapper)children[i]).getErrorCount();
            }
        }
        return result;
    }

    @Override
    public String getRealPath(String path) {
        // The WebResources API expects all paths to start with /. This is a
        // special case for consistency with earlier Tomcat versions.
        if ("".equals(path)) {
            path = "/";
        }
        if (resources != null) {
            try {
                WebResource resource = resources.getResource(path);
                String canonicalPath = resource.getCanonicalPath();
                if (canonicalPath == null) {
                    return null;
                } else if ((resource.isDirectory() && !canonicalPath.endsWith(File.separator) ||
                        !resource.exists()) && path.endsWith("/")) {
                    return canonicalPath + File.separatorChar;
                } else {
                    return canonicalPath;
                }
            } catch (IllegalArgumentException iae) {
                // ServletContext.getRealPath() does not allow this to be thrown
            }
        }
        return null;
    }

    
    @Deprecated
    public ServletRegistration.Dynamic dynamicServletAdded(Wrapper wrapper) {
        return new ApplicationServletRegistration(wrapper, this);
    }

    public void dynamicServletCreated(Servlet servlet) {
        createdServlets.add(servlet);
    }

    public boolean wasCreatedDynamicServlet(Servlet servlet) {
        return createdServlets.contains(servlet);
    }

    /**
     * A helper class to manage the filter mappings in a Context.
     */
    private static final class ContextFilterMaps {
        private final Object lock = new Object();

        private FilterMap[] array = new FilterMap[0];

        private int insertPoint = 0;

        public FilterMap[] asArray() {
            synchronized (lock) {
                return array;
            }
        }

        public void add(FilterMap filterMap) {
            synchronized (lock) {
                FilterMap results[] = Arrays.copyOf(array, array.length + 1);
                results[array.length] = filterMap;
                array = results;
            }
        }

        public void addBefore(FilterMap filterMap) {
            synchronized (lock) {
                FilterMap results[] = new FilterMap[array.length + 1];
                System.arraycopy(array, 0, results, 0, insertPoint);
                System.arraycopy(array, insertPoint, results, insertPoint + 1,
                        array.length - insertPoint);
                results[insertPoint] = filterMap;
                array = results;
                insertPoint++;
            }
        }

        public void remove(FilterMap filterMap) {
            synchronized (lock) {
                // Make sure this filter mapping is currently present
                int n = -1;
                for (int i = 0; i < array.length; i++) {
                    if (array[i] == filterMap) {
                        n = i;
                        break;
                    }
                }
                if (n < 0)
                    return;

                // Remove the specified filter mapping
                FilterMap results[] = new FilterMap[array.length - 1];
                System.arraycopy(array, 0, results, 0, n);
                System.arraycopy(array, n + 1, results, n, (array.length - 1)
                        - n);
                array = results;
                if (n < insertPoint) {
                    insertPoint--;
                }
            }
        }
    }

    // --------------------------------------------------------- Public Methods

    public boolean filterStart() {
        if (getLogger().isDebugEnabled()) {
            getLogger().debug("Starting filters");
        }
        // Instantiate and record a FilterConfig for each defined filter
        boolean ok = true;
        synchronized (filterConfigs) {
            filterConfigs.clear();
            for (Entry<String,FilterDef> entry : filterDefs.entrySet()) {
                String name = entry.getKey();
                if (getLogger().isDebugEnabled()) {
                    getLogger().debug(" Starting filter '" + name + "'");
                }
                try {
                    ApplicationFilterConfig filterConfig =
                            new ApplicationFilterConfig(this, entry.getValue());
                    filterConfigs.put(name, filterConfig);
                } catch (Throwable t) {
                    t = ExceptionUtils.unwrapInvocationTargetException(t);
                    ExceptionUtils.handleThrowable(t);
                    getLogger().error(sm.getString(
                            "standardContext.filterStart", name), t);
                    ok = false;
                }
            }
        }
        return ok;
    }

    public boolean filterStop() {
        if (getLogger().isDebugEnabled())
            getLogger().debug("Stopping filters");
        // Release all Filter and FilterConfig instances
        synchronized (filterConfigs) {
            for (Entry<String, ApplicationFilterConfig> entry : filterConfigs.entrySet()) {
                if (getLogger().isDebugEnabled())
                    getLogger().debug(" Stopping filter '" + entry.getKey() + "'");
                ApplicationFilterConfig filterConfig = entry.getValue();
                filterConfig.release();
            }
            filterConfigs.clear();
        }
        return (true);
    }

    public FilterConfig findFilterConfig(String name) {
        return (filterConfigs.get(name));
    }

    public boolean listenerStart() {
        if (log.isDebugEnabled())
            log.debug("Configuring application event listeners");
        // Instantiate the required listeners
        String listeners[] = findApplicationListeners();
        Object results[] = new Object[listeners.length];
        boolean ok = true;
        for (int i = 0; i < results.length; i++) {
            if (getLogger().isDebugEnabled())
                getLogger().debug(" Configuring event listener class '" +
                    listeners[i] + "'");
            try {
                String listener = listeners[i];
                results[i] = getInstanceManager().newInstance(listener);
            } catch (Throwable t) {
                t = ExceptionUtils.unwrapInvocationTargetException(t);
                ExceptionUtils.handleThrowable(t);
                getLogger().error(sm.getString(
                        "standardContext.applicationListener", listeners[i]), t);
                ok = false;
            }
        }
        if (!ok) {
            getLogger().error(sm.getString("standardContext.applicationSkipped"));
            return (false);
        }
        // Sort listeners in two arrays
        ArrayList<Object> eventListeners = new ArrayList<>();
        ArrayList<Object> lifecycleListeners = new ArrayList<>();
        for (int i = 0; i < results.length; i++) {
            if ((results[i] instanceof ServletContextAttributeListener)
                || (results[i] instanceof ServletRequestAttributeListener)
                || (results[i] instanceof ServletRequestListener)
                || (results[i] instanceof HttpSessionIdListener)
                || (results[i] instanceof HttpSessionAttributeListener)) {
                eventListeners.add(results[i]);
            }
            if ((results[i] instanceof ServletContextListener)
                || (results[i] instanceof HttpSessionListener)) {
                lifecycleListeners.add(results[i]);
            }
        }
        // Listener instances may have been added directly to this Context by
        // ServletContextInitializers and other code via the pluggability APIs.
        // Put them these listeners after the ones defined in web.xml and/or
        // annotations then overwrite the list of instances with the new, full
        // list.
        for (Object eventListener: getApplicationEventListeners()) {
            eventListeners.add(eventListener);
        }
        setApplicationEventListeners(eventListeners.toArray());
        for (Object lifecycleListener: getApplicationLifecycleListeners()) {
            lifecycleListeners.add(lifecycleListener);
            if (lifecycleListener instanceof ServletContextListener) {
                noPluggabilityListeners.add(lifecycleListener);
            }
        }
        setApplicationLifecycleListeners(lifecycleListeners.toArray());
        // Send application start events
        if (getLogger().isDebugEnabled())
            getLogger().debug("Sending application start events");
        // Ensure context is not null
        getServletContext();
        context.setNewServletContextListenerAllowed(false);
        Object instances[] = getApplicationLifecycleListeners();
        if (instances == null || instances.length == 0) {
            return ok;
        }
        ServletContextEvent event = new ServletContextEvent(getServletContext());
        ServletContextEvent tldEvent = null;
        if (noPluggabilityListeners.size() > 0) {
            noPluggabilityServletContext = new NoPluggabilityServletContext(getServletContext());
            tldEvent = new ServletContextEvent(noPluggabilityServletContext);
        }
        for (int i = 0; i < instances.length; i++) {
            if (!(instances[i] instanceof ServletContextListener))
                continue;
            ServletContextListener listener =
                (ServletContextListener) instances[i];
            try {
                fireContainerEvent("beforeContextInitialized", listener);
                if (noPluggabilityListeners.contains(listener)) {
                    listener.contextInitialized(tldEvent);
                } else {
                    listener.contextInitialized(event);
                }
                fireContainerEvent("afterContextInitialized", listener);
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                fireContainerEvent("afterContextInitialized", listener);
                getLogger().error
                    (sm.getString("standardContext.listenerStart",
                                  instances[i].getClass().getName()), t);
                ok = false;
            }
        }
        return (ok);
    }

    public boolean listenerStop() {
        if (log.isDebugEnabled())
            log.debug("Sending application stop events");
        boolean ok = true;
        Object listeners[] = getApplicationLifecycleListeners();
        if (listeners != null && listeners.length > 0) {
            ServletContextEvent event = new ServletContextEvent(getServletContext());
            ServletContextEvent tldEvent = null;
            if (noPluggabilityServletContext != null) {
                tldEvent = new ServletContextEvent(noPluggabilityServletContext);
            }
            for (int i = 0; i < listeners.length; i++) {
                int j = (listeners.length - 1) - i;
                if (listeners[j] == null)
                    continue;
                if (listeners[j] instanceof ServletContextListener) {
                    ServletContextListener listener =
                        (ServletContextListener) listeners[j];
                    try {
                        fireContainerEvent("beforeContextDestroyed", listener);
                        if (noPluggabilityListeners.contains(listener)) {
                            listener.contextDestroyed(tldEvent);
                        } else {
                            listener.contextDestroyed(event);
                        }
                        fireContainerEvent("afterContextDestroyed", listener);
                    } catch (Throwable t) {
                        ExceptionUtils.handleThrowable(t);
                        fireContainerEvent("afterContextDestroyed", listener);
                        getLogger().error
                            (sm.getString("standardContext.listenerStop",
                                listeners[j].getClass().getName()), t);
                        ok = false;
                    }
                }
                try {
                    if (getInstanceManager() != null) {
                        getInstanceManager().destroyInstance(listeners[j]);
                    }
                } catch (Throwable t) {
                    t = ExceptionUtils.unwrapInvocationTargetException(t);
                    ExceptionUtils.handleThrowable(t);
                    getLogger().error
                       (sm.getString("standardContext.listenerStop",
                            listeners[j].getClass().getName()), t);
                    ok = false;
                }
            }
        }
        // Annotation processing
        listeners = getApplicationEventListeners();
        if (listeners != null) {
            for (int i = 0; i < listeners.length; i++) {
                int j = (listeners.length - 1) - i;
                if (listeners[j] == null)
                    continue;
                try {
                    if (getInstanceManager() != null) {
                        getInstanceManager().destroyInstance(listeners[j]);
                    }
                } catch (Throwable t) {
                    t = ExceptionUtils.unwrapInvocationTargetException(t);
                    ExceptionUtils.handleThrowable(t);
                    getLogger().error
                        (sm.getString("standardContext.listenerStop",
                            listeners[j].getClass().getName()), t);
                    ok = false;
                }
            }
        }
        setApplicationEventListeners(null);
        setApplicationLifecycleListeners(null);
        noPluggabilityServletContext = null;
        noPluggabilityListeners.clear();
        return ok;
    }

    public void resourcesStart() throws LifecycleException {
        if (!resources.getState().isAvailable()) {
            resources.start();
        }
        if (effectiveMajorVersion >=3 && addWebinfClassesResources) {
            WebResource webinfClassesResource = resources.getResource(
                    "/WEB-INF/classes/META-INF/resources");
            if (webinfClassesResource.isDirectory()) {
                getResources().createWebResourceSet(
                        WebResourceRoot.ResourceSetType.RESOURCE_JAR, "/",
                        webinfClassesResource.getURL(), "/");
            }
        }
    }


    public boolean resourcesStop() {
        boolean ok = true;
        Lock writeLock = resourcesLock.writeLock();
        writeLock.lock();
        try {
            if (resources != null) {
                resources.stop();
            }
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            log.error(sm.getString("standardContext.resourcesStop"), t);
            ok = false;
        } finally {
            writeLock.unlock();
        }
        return ok;
    }


    public boolean loadOnStartup(Container children[]) {
        // Collect "load on startup" servlets that need to be initialized
        TreeMap<Integer, ArrayList<Wrapper>> map = new TreeMap<>();
        for (int i = 0; i < children.length; i++) {
            Wrapper wrapper = (Wrapper) children[i];
            int loadOnStartup = wrapper.getLoadOnStartup();
            if (loadOnStartup < 0)
                continue;
            Integer key = Integer.valueOf(loadOnStartup);
            ArrayList<Wrapper> list = map.get(key);
            if (list == null) {
                list = new ArrayList<>();
                map.put(key, list);
            }
            list.add(wrapper);
        }
        // Load the collected "load on startup" servlets
        for (ArrayList<Wrapper> list : map.values()) {
            for (Wrapper wrapper : list) {
                try {
                    wrapper.load();
                } catch (ServletException e) {
                    getLogger().error(sm.getString("standardContext.loadOnStartup.loadException",
                          getName(), wrapper.getName()), StandardWrapper.getRootCause(e));
                    // NOTE: load errors (including a servlet that throws
                    // UnavailableException from the init() method) are NOT
                    // fatal to application startup
                    // unless failCtxIfServletStartFails="true" is specified
                    if(getComputedFailCtxIfServletStartFails()) {
                        return false;
                    }
                }
            }
        }
        return true;
    }


    @Override
    protected synchronized void startInternal() throws LifecycleException {
        if(log.isDebugEnabled())
            log.debug("Starting " + getBaseName());
        // Send j2ee.state.starting notification
        if (this.getObjectName() != null) {
            Notification notification = new Notification("j2ee.state.starting",
                    this.getObjectName(), sequenceNumber.getAndIncrement());
            broadcaster.sendNotification(notification);
        }
        // 将configured属性设置为false
        setConfigured(false);
        boolean ok = true;
        // Currently this is effectively a NO-OP but needs to be called to
        // ensure the NamingResources follows the correct lifecycle
        if (namingResources != null) {
            namingResources.start();
        }
        // Post work directory
        postWorkDirectory();
        // 配置资源
        if (getResources() == null) {   // (1) Required by Loader
            if (log.isDebugEnabled())
                log.debug("Configuring default Resources");
            try {
                setResources(new StandardRoot(this));
            } catch (IllegalArgumentException e) {
                log.error(sm.getString("standardContext.resourcesInit"), e);
                ok = false;
            }
        }
        if (ok) {
            resourcesStart();
        }
        //设置加载器
        if (getLoader() == null) {
            WebappLoader webappLoader = new WebappLoader(getParentClassLoader());
            webappLoader.setDelegate(getDelegate());
            setLoader(webappLoader);
        }

        // An explicit cookie processor hasn't been specified; use the default
        if (cookieProcessor == null) {
            cookieProcessor = new LegacyCookieProcessor();
        }

        // 初始化字符集映射器
        getCharsetMapper();

        // Validate required extensions
        boolean dependencyCheck = true;
        try {
            dependencyCheck = ExtensionValidator.validateApplication
                (getResources(), this);
        } catch (IOException ioe) {
            log.error(sm.getString("standardContext.extensionValidationError"), ioe);
            dependencyCheck = false;
        }

        if (!dependencyCheck) {
            // do not make application available if dependency check fails
            ok = false;
        }

        // Reading the "catalina.useNaming" environment variable
        String useNamingProperty = System.getProperty("catalina.useNaming");
        if ((useNamingProperty != null)
            && (useNamingProperty.equals("false"))) {
            useNaming = false;
        }

        if (ok && isUseNaming()) {
            if (getNamingContextListener() == null) {
                NamingContextListener ncl = new NamingContextListener();
                ncl.setName(getNamingContextName());
                ncl.setExceptionOnFailedWrite(getJndiExceptionOnFailedWrite());
                addLifecycleListener(ncl);
                setNamingContextListener(ncl);
            }
        }

        // Standard container startup
        if (log.isDebugEnabled())
            log.debug("Processing standard container startup");

        // Binding thread
        ClassLoader oldCCL = bindThread();
        //启动与该Context容器相关的组件
        try {
            if (ok) {
                // Start our subordinate components, if any
                Loader loader = getLoader();
                if ((loader != null) && (loader instanceof Lifecycle))
                    ((Lifecycle) loader).start();

                // since the loader just started, the webapp classloader is now
                // created.
                setClassLoaderProperty("clearReferencesRmiTargets",
                        getClearReferencesRmiTargets());
                setClassLoaderProperty("clearReferencesStatic",
                        getClearReferencesStatic());
                setClassLoaderProperty("clearReferencesStopThreads",
                        getClearReferencesStopThreads());
                setClassLoaderProperty("clearReferencesStopTimerThreads",
                        getClearReferencesStopTimerThreads());
                setClassLoaderProperty("clearReferencesHttpClientKeepAliveThread",
                        getClearReferencesHttpClientKeepAliveThread());

                // By calling unbindThread and bindThread in a row, we setup the
                // current Thread CCL to be the webapp classloader
                unbindThread(oldCCL);
                oldCCL = bindThread();

                // Initialize logger again. Other components might have used it
                // too early, so it should be reset.
                logger = null;
                getLogger();

                Realm realm = getRealmInternal();

                if (realm != null) {
                    if (realm instanceof Lifecycle)
                        ((Lifecycle) realm).start();

                    // Place the CredentialHandler into the ServletContext so
                    // applications can have access to it. Wrap it in a "safe"
                    // handler so application's can't modify it.
                    CredentialHandler safeHandler = new CredentialHandler() {
                        @Override
                        public boolean matches(String inputCredentials, String storedCredentials) {
                            return getRealmInternal().getCredentialHandler().matches(inputCredentials, storedCredentials);
                        }

                        @Override
                        public String mutate(String inputCredentials) {
                            return getRealmInternal().getCredentialHandler().mutate(inputCredentials);
                        }
                    };
                    context.setAttribute(Globals.CREDENTIAL_HANDLER, safeHandler);
                }

                // Notify our interested LifecycleListeners
                fireLifecycleEvent(Lifecycle.CONFIGURE_START_EVENT, null);

                // Start our child containers, if not already started
                for (Container child : findChildren()) {
                    if (!child.getState().isAvailable()) {
                        child.start();
                    }
                }

                // Start the Valves in our pipeline (including the basic),
                // if any
                if (pipeline instanceof Lifecycle) {
                    ((Lifecycle) pipeline).start();
                }
                // Acquire clustered manager
                Manager contextManager = null;
                Manager manager = getManager();
                if (manager == null) {
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("standardContext.cluster.noManager",
                                Boolean.valueOf((getCluster() != null)),
                                Boolean.valueOf(distributable)));
                    }
                    if ( (getCluster() != null) && distributable) {
                        try {
                            contextManager = getCluster().createManager(getName());
                        } catch (Exception ex) {
                            log.error("standardContext.clusterFail", ex);
                            ok = false;
                        }
                    } else {
                        contextManager = new StandardManager();
                    }
                }

                // Configure default manager if none was specified
                if (contextManager != null) {
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("standardContext.manager",
                                contextManager.getClass().getName()));
                    }
                    setManager(contextManager);
                }

                if (manager!=null && (getCluster() != null) && distributable) {
                    //let the cluster know that there is a context that is distributable
                    //and that it has its own manager
                    getCluster().registerManager(manager);
                }
            }

            if (!getConfigured()) {
                log.error(sm.getString("standardContext.configurationFail"));
                ok = false;
            }

            // We put the resources into the servlet context
            if (ok)
                getServletContext().setAttribute
                    (Globals.RESOURCES_ATTR, getResources());

            if (ok ) {
                if (getInstanceManager() == null) {
                    javax.naming.Context context = null;
                    if (isUseNaming() && getNamingContextListener() != null) {
                        context = getNamingContextListener().getEnvContext();
                    }
                    Map<String, Map<String, String>> injectionMap = buildInjectionMap(
                            getIgnoreAnnotations() ? new NamingResourcesImpl(): getNamingResources());
                    setInstanceManager(new DefaultInstanceManager(context,
                            injectionMap, this, this.getClass().getClassLoader()));
                    getServletContext().setAttribute(
                            InstanceManager.class.getName(), getInstanceManager());
                }
            }

            // Create context attributes that will be required
            if (ok) {
                getServletContext().setAttribute(
                        JarScanner.class.getName(), getJarScanner());
            }

            // Set up the context init params
            mergeParameters();

            // Call ServletContainerInitializers
            for (Map.Entry<ServletContainerInitializer, Set<Class<?>>> entry :
                initializers.entrySet()) {
                try {
                    entry.getKey().onStartup(entry.getValue(),
                            getServletContext());
                } catch (ServletException e) {
                    log.error(sm.getString("standardContext.sciFail"), e);
                    ok = false;
                    break;
                }
            }

            // Configure and call application event listeners
            if (ok) {
                if (!listenerStart()) {
                    log.error(sm.getString("standardContext.listenerFail"));
                    ok = false;
                }
            }

            // Check constraints for uncovered HTTP methods
            // Needs to be after SCIs and listeners as they may programmatically
            // change constraints
            if (ok) {
                checkConstraintsForUncoveredMethods(findConstraints());
            }

            try {
                // Start manager
                Manager manager = getManager();
                if ((manager != null) && (manager instanceof Lifecycle)) {
                    ((Lifecycle) manager).start();
                }
            } catch(Exception e) {
                log.error(sm.getString("standardContext.managerFail"), e);
                ok = false;
            }

            // Configure and call application filters
            if (ok) {
                if (!filterStart()) {
                    log.error(sm.getString("standardContext.filterFail"));
                    ok = false;
                }
            }

            // Load and initialize all "load on startup" servlets
            if (ok) {
                if (!loadOnStartup(findChildren())){
                    log.error(sm.getString("standardContext.servletFail"));
                    ok = false;
                }
            }

            // Start ContainerBackgroundProcessor thread
            super.threadStart();
        } finally {
            // Unbinding thread
            unbindThread(oldCCL);
        }

        // Set available status depending upon startup success
        if (ok) {
            if (log.isDebugEnabled())
                log.debug("Starting completed");
        } else {
            log.error(sm.getString("standardContext.startFailed", getName()));
        }

        startTime=System.currentTimeMillis();

        // Send j2ee.state.running notification
        if (ok && (this.getObjectName() != null)) {
            Notification notification =
                new Notification("j2ee.state.running", this.getObjectName(),
                                 sequenceNumber.getAndIncrement());
            broadcaster.sendNotification(notification);
        }

        // The WebResources implementation caches references to JAR files. On
        // some platforms these references may lock the JAR files. Since web
        // application start is likely to have read from lots of JARs, trigger
        // a clean-up now.
        getResources().gc();

        // Reinitializing if something went wrong
        if (!ok) {
            setState(LifecycleState.FAILED);
        } else {
            setState(LifecycleState.STARTING);
        }
    }

    private void checkConstraintsForUncoveredMethods(
            SecurityConstraint[] constraints) {
        SecurityConstraint[] newConstraints =
                SecurityConstraint.findUncoveredHttpMethods(constraints,
                        getDenyUncoveredHttpMethods(), getLogger());
        for (SecurityConstraint constraint : newConstraints) {
            addConstraint(constraint);
        }
    }

    private void setClassLoaderProperty(String name, boolean value) {
        ClassLoader cl = getLoader().getClassLoader();
        if (!IntrospectionUtils.setProperty(cl, name, Boolean.toString(value))) {
            // Failed to set
            log.info(sm.getString(
                    "standardContext.webappClassLoader.missingProperty",
                    name, Boolean.toString(value)));
        }
    }

    private Map<String, Map<String, String>> buildInjectionMap(NamingResourcesImpl namingResources) {
        Map<String, Map<String, String>> injectionMap = new HashMap<>();
        for (Injectable resource: namingResources.findLocalEjbs()) {
            addInjectionTarget(resource, injectionMap);
        }
        for (Injectable resource: namingResources.findEjbs()) {
            addInjectionTarget(resource, injectionMap);
        }
        for (Injectable resource: namingResources.findEnvironments()) {
            addInjectionTarget(resource, injectionMap);
        }
        for (Injectable resource: namingResources.findMessageDestinationRefs()) {
            addInjectionTarget(resource, injectionMap);
        }
        for (Injectable resource: namingResources.findResourceEnvRefs()) {
            addInjectionTarget(resource, injectionMap);
        }
        for (Injectable resource: namingResources.findResources()) {
            addInjectionTarget(resource, injectionMap);
        }
        for (Injectable resource: namingResources.findServices()) {
            addInjectionTarget(resource, injectionMap);
        }
        return injectionMap;
    }

    private void addInjectionTarget(Injectable resource, Map<String, Map<String, String>> injectionMap) {
        List<InjectionTarget> injectionTargets = resource.getInjectionTargets();
        if (injectionTargets != null && injectionTargets.size() > 0) {
            String jndiName = resource.getName();
            for (InjectionTarget injectionTarget: injectionTargets) {
                String clazz = injectionTarget.getTargetClass();
                Map<String, String> injections = injectionMap.get(clazz);
                if (injections == null) {
                    injections = new HashMap<>();
                    injectionMap.put(clazz, injections);
                }
                injections.put(injectionTarget.getTargetName(), jndiName);
            }
        }
    }

    private void mergeParameters() {
        Map<String,String> mergedParams = new HashMap<>();

        String names[] = findParameters();
        for (int i = 0; i < names.length; i++) {
            mergedParams.put(names[i], findParameter(names[i]));
        }

        ApplicationParameter params[] = findApplicationParameters();
        for (int i = 0; i < params.length; i++) {
            if (params[i].getOverride()) {
                if (mergedParams.get(params[i].getName()) == null) {
                    mergedParams.put(params[i].getName(),
                            params[i].getValue());
                }
            } else {
                mergedParams.put(params[i].getName(), params[i].getValue());
            }
        }

        ServletContext sc = getServletContext();
        for (Map.Entry<String,String> entry : mergedParams.entrySet()) {
            sc.setInitParameter(entry.getKey(), entry.getValue());
        }

    }

    @Override
    protected synchronized void stopInternal() throws LifecycleException {

        // Send j2ee.state.stopping notification
        if (this.getObjectName() != null) {
            Notification notification =
                new Notification("j2ee.state.stopping", this.getObjectName(),
                                 sequenceNumber.getAndIncrement());
            broadcaster.sendNotification(notification);
        }

        setState(LifecycleState.STOPPING);

        // Binding thread
        ClassLoader oldCCL = bindThread();

        try {
            // Stop our child containers, if any
            final Container[] children = findChildren();

            // Stop ContainerBackgroundProcessor thread
            threadStop();

            for (int i = 0; i < children.length; i++) {
                children[i].stop();
            }

            // Stop our filters
            filterStop();

            Manager manager = getManager();
            if (manager != null && manager instanceof Lifecycle &&
                    ((Lifecycle) manager).getState().isAvailable()) {
                ((Lifecycle) manager).stop();
            }

            // Stop our application listeners
            listenerStop();

            // Finalize our character set mapper
            setCharsetMapper(null);

            // Normal container shutdown processing
            if (log.isDebugEnabled())
                log.debug("Processing standard container shutdown");

            // JNDI resources are unbound in CONFIGURE_STOP_EVENT so stop
            // naming resources before they are unbound since NamingResources
            // does a JNDI lookup to retrieve the resource. This needs to be
            // after the application has finished with the resource
            if (namingResources != null) {
                namingResources.stop();
            }

            fireLifecycleEvent(Lifecycle.CONFIGURE_STOP_EVENT, null);

            // Stop the Valves in our pipeline (including the basic), if any
            if (pipeline instanceof Lifecycle &&
                    ((Lifecycle) pipeline).getState().isAvailable()) {
                ((Lifecycle) pipeline).stop();
            }

            // Clear all application-originated servlet context attributes
            if (context != null)
                context.clearAttributes();

            Realm realm = getRealmInternal();
            if ((realm != null) && (realm instanceof Lifecycle)) {
                ((Lifecycle) realm).stop();
            }
            Loader loader = getLoader();
            if ((loader != null) && (loader instanceof Lifecycle)) {
                ((Lifecycle) loader).stop();
            }

            // Stop resources
            resourcesStop();

        } finally {

            // Unbinding thread
            unbindThread(oldCCL);

        }

        // Send j2ee.state.stopped notification
        if (this.getObjectName() != null) {
            Notification notification =
                new Notification("j2ee.state.stopped", this.getObjectName(),
                                sequenceNumber.getAndIncrement());
            broadcaster.sendNotification(notification);
        }

        // Reset application context
        context = null;

        // This object will no longer be visible or used.
        try {
            resetContext();
        } catch( Exception ex ) {
            log.error( "Error resetting context " + this + " " + ex, ex );
        }

        //reset the instance manager
        setInstanceManager(null);

        if (log.isDebugEnabled())
            log.debug("Stopping complete");

    }

    @Override
    protected void destroyInternal() throws LifecycleException {

        // If in state NEW when destroy is called, the object name will never
        // have been set so the notification can't be created
        if (getObjectName() != null) {
            // Send j2ee.object.deleted notification
            Notification notification =
                new Notification("j2ee.object.deleted", this.getObjectName(),
                                 sequenceNumber.getAndIncrement());
            broadcaster.sendNotification(notification);
        }

        if (namingResources != null) {
            namingResources.destroy();
        }

        synchronized (instanceListenersLock) {
            instanceListeners = new String[0];
        }

        Loader loader = getLoader();
        if ((loader != null) && (loader instanceof Lifecycle)) {
            ((Lifecycle) loader).destroy();
        }

        Manager manager = getManager();
        if ((manager != null) && (manager instanceof Lifecycle)) {
            ((Lifecycle) manager).destroy();
        }

        if (resources != null) {
            resources.destroy();
        }

        super.destroyInternal();
    }


    /**
	 * 所有后台运行的共享同一个线程,包括session管理,类加载器等操作,共享线程在ContainerBase中创建,调用ContainerBase中的threadStart启动后台线程
     */
    @Override
    public void backgroundProcess() {
        if (!getState().isAvailable())
            return;
        //类加载器执行的任务
        Loader loader = getLoader();
        if (loader != null) {
            try {
                loader.backgroundProcess();
            } catch (Exception e) {
                log.warn(sm.getString(
                        "standardContext.backgroundProcess.loader", loader), e);
            }
        }
        //session管理器执行的任务
        Manager manager = getManager();
        if (manager != null) {
            try {
                manager.backgroundProcess();
            } catch (Exception e) {
                log.warn(sm.getString(
                        "standardContext.backgroundProcess.manager", manager),
                        e);
            }
        }
        //资源管理器执行的任务
        WebResourceRoot resources = getResources();
        if (resources != null) {
            try {
                resources.backgroundProcess();
            } catch (Exception e) {
                log.warn(sm.getString(
                        "standardContext.backgroundProcess.resources",
                        resources), e);
            }
        }
        //实例管理器执行任务
        InstanceManager instanceManager = getInstanceManager();
        if (instanceManager instanceof DefaultInstanceManager) {
            try {
                ((DefaultInstanceManager) instanceManager).backgroundProcess();
            } catch (Exception e) {
                log.warn(sm.getString(
                        "standardContext.backgroundProcess.instanceManager",
                        resources), e);
            }
        }
        super.backgroundProcess();
    }

    private void resetContext() throws Exception {
        // Restore the original state ( pre reading web.xml in start )
        // If you extend this - override this method and make sure to clean up

        // Don't reset anything that is read from a <Context.../> element since
        // <Context .../> elements are read at initialisation will not be read
        // again for this object
        for (Container child : findChildren()) {
            removeChild(child);
        }
        startupTime = 0;
        startTime = 0;
        tldScanTime = 0;

        // Bugzilla 32867
        distributable = false;

        applicationListeners = new String[0];
        applicationEventListenersList.clear();
        applicationLifecycleListenersObjects = new Object[0];
        jspConfigDescriptor = null;

        initializers.clear();

        createdServlets.clear();

        postConstructMethods.clear();
        preDestroyMethods.clear();

        if(log.isDebugEnabled())
            log.debug("resetContext " + getObjectName());
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        if (getParent() != null) {
            sb.append(getParent().toString());
            sb.append(".");
        }
        sb.append("StandardContext[");
        sb.append(getName());
        sb.append("]");
        return (sb.toString());

    }


    // ------------------------------------------------------ Protected Methods

    protected String adjustURLPattern(String urlPattern) {

        if (urlPattern == null)
            return (urlPattern);
        if (urlPattern.startsWith("/") || urlPattern.startsWith("*."))
            return (urlPattern);
        if (!isServlet22())
            return (urlPattern);
        if(log.isDebugEnabled())
            log.debug(sm.getString("standardContext.urlPattern.patternWarning",
                         urlPattern));
        return ("/" + urlPattern);

    }

    @Override
    public boolean isServlet22() {
        return XmlIdentifiers.WEB_22_PUBLIC.equals(publicId);
    }

    @Override
    public Set<String> addServletSecurity(
            ServletRegistration.Dynamic registration,
            ServletSecurityElement servletSecurityElement) {

        Set<String> conflicts = new HashSet<>();

        Collection<String> urlPatterns = registration.getMappings();
        for (String urlPattern : urlPatterns) {
            boolean foundConflict = false;

            SecurityConstraint[] securityConstraints =
                findConstraints();
            for (SecurityConstraint securityConstraint : securityConstraints) {

                SecurityCollection[] collections =
                    securityConstraint.findCollections();
                for (SecurityCollection collection : collections) {
                    if (collection.findPattern(urlPattern)) {
                        // First pattern found will indicate if there is a
                        // conflict since for any given pattern all matching
                        // constraints will be from either the descriptor or
                        // not. It is not permitted to have a mixture
                        if (collection.isFromDescriptor()) {
                            // Skip this pattern
                            foundConflict = true;
                            conflicts.add(urlPattern);
                            break;
                        } else {
                            // Need to overwrite constraint for this pattern
                            collection.removePattern(urlPattern);
                            // If the collection is now empty, remove it
                            if (collection.findPatterns().length == 0) {
                                securityConstraint.removeCollection(collection);
                            }
                        }
                    }
                }

                // If the constraint now has no collections - remove it
                if (securityConstraint.findCollections().length == 0) {
                    removeConstraint(securityConstraint);
                }

                // No need to check other constraints for the current pattern
                // once a conflict has been found
                if (foundConflict) {
                    break;
                }
            }

            // Note: For programmatically added Servlets this may not be the
            //       complete set of security constraints since additional
            //       URL patterns can be added after the application has called
            //       setSecurity. For all programmatically added servlets, the
            //       #dynamicServletAdded() method sets a flag that ensures that
            //       the constraints are re-evaluated before the servlet is
            //       first used

            // If the pattern did not conflict, add the new constraint(s).
            if (!foundConflict) {
                SecurityConstraint[] newSecurityConstraints =
                        SecurityConstraint.createConstraints(
                                servletSecurityElement,
                                urlPattern);
                for (SecurityConstraint securityConstraint :
                        newSecurityConstraints) {
                    addConstraint(securityConstraint);
                }
            }
        }

        return conflicts;
    }

    protected ClassLoader bindThread() {
        ClassLoader oldContextClassLoader = bind(false, null);
        if (isUseNaming()) {
            try {
                ContextBindings.bindThread(this, getNamingToken());
            } catch (NamingException e) {
                // Silent catch, as this is a normal case during the early
                // startup stages
            }
        }
        return oldContextClassLoader;
    }

    protected void unbindThread(ClassLoader oldContextClassLoader) {
        if (isUseNaming()) {
            ContextBindings.unbindThread(this, getNamingToken());
        }
        unbind(false, oldContextClassLoader);
    }


    @Override
    public ClassLoader bind(boolean usePrivilegedAction, ClassLoader originalClassLoader) {
        Loader loader = getLoader();
        ClassLoader webApplicationClassLoader = null;
        if (loader != null) {
            webApplicationClassLoader = loader.getClassLoader();
        }

        if (originalClassLoader == null) {
            if (usePrivilegedAction) {
                PrivilegedAction<ClassLoader> pa = new PrivilegedGetTccl();
                originalClassLoader = AccessController.doPrivileged(pa);
            } else {
                originalClassLoader = Thread.currentThread().getContextClassLoader();
            }
        }

        if (webApplicationClassLoader == null ||
                webApplicationClassLoader == originalClassLoader) {
            // Not possible or not necessary to switch class loaders. Return
            // null to indicate this.
            return null;
        }

        ThreadBindingListener threadBindingListener = getThreadBindingListener();

        if (usePrivilegedAction) {
            PrivilegedAction<Void> pa = new PrivilegedSetTccl(webApplicationClassLoader);
            AccessController.doPrivileged(pa);
        } else {
            Thread.currentThread().setContextClassLoader(webApplicationClassLoader);
        }
        if (threadBindingListener != null) {
            try {
                threadBindingListener.bind();
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.error(sm.getString(
                        "standardContext.threadBindingListenerError", getName()), t);
            }
        }

        return originalClassLoader;
    }


    @Override
    public void unbind(boolean usePrivilegedAction, ClassLoader originalClassLoader) {
        if (originalClassLoader == null) {
            return;
        }

        if (threadBindingListener != null) {
            try {
                threadBindingListener.unbind();
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.error(sm.getString(
                        "standardContext.threadBindingListenerError", getName()), t);
            }
        }

        if (usePrivilegedAction) {
            PrivilegedAction<Void> pa = new PrivilegedSetTccl(originalClassLoader);
            AccessController.doPrivileged(pa);
        } else {
            Thread.currentThread().setContextClassLoader(originalClassLoader);
        }
    }

    private String getNamingContextName() {
        if (namingContextName == null) {
            Container parent = getParent();
            if (parent == null) {
            namingContextName = getName();
            } else {
            Stack<String> stk = new Stack<>();
            StringBuilder buff = new StringBuilder();
            while (parent != null) {
                stk.push(parent.getName());
                parent = parent.getParent();
            }
            while (!stk.empty()) {
                buff.append("/" + stk.pop());
            }
            buff.append(getName());
            namingContextName = buff.toString();
            }
        }
        return namingContextName;
    }

    public NamingContextListener getNamingContextListener() {
        return namingContextListener;
    }


    public void setNamingContextListener(NamingContextListener namingContextListener) {
        this.namingContextListener = namingContextListener;
    }

    @Override
    public boolean getPaused() {
        return (this.paused);
    }

    @Override
    public boolean fireRequestInitEvent(ServletRequest request) {

        Object instances[] = getApplicationEventListeners();

        if ((instances != null) && (instances.length > 0)) {

            ServletRequestEvent event =
                    new ServletRequestEvent(getServletContext(), request);

            for (int i = 0; i < instances.length; i++) {
                if (instances[i] == null)
                    continue;
                if (!(instances[i] instanceof ServletRequestListener))
                    continue;
                ServletRequestListener listener =
                    (ServletRequestListener) instances[i];

                try {
                    listener.requestInitialized(event);
                } catch (Throwable t) {
                    ExceptionUtils.handleThrowable(t);
                    getLogger().error(sm.getString(
                            "standardContext.requestListener.requestInit",
                            instances[i].getClass().getName()), t);
                    request.setAttribute(RequestDispatcher.ERROR_EXCEPTION, t);
                    return false;
                }
            }
        }
        return true;
    }


    @Override
    public boolean fireRequestDestroyEvent(ServletRequest request) {
        Object instances[] = getApplicationEventListeners();

        if ((instances != null) && (instances.length > 0)) {

            ServletRequestEvent event =
                new ServletRequestEvent(getServletContext(), request);

            for (int i = 0; i < instances.length; i++) {
                int j = (instances.length -1) -i;
                if (instances[j] == null)
                    continue;
                if (!(instances[j] instanceof ServletRequestListener))
                    continue;
                ServletRequestListener listener =
                    (ServletRequestListener) instances[j];

                try {
                    listener.requestDestroyed(event);
                } catch (Throwable t) {
                    ExceptionUtils.handleThrowable(t);
                    getLogger().error(sm.getString(
                            "standardContext.requestListener.requestInit",
                            instances[j].getClass().getName()), t);
                    request.setAttribute(RequestDispatcher.ERROR_EXCEPTION, t);
                    return false;
                }
            }
        }
        return true;
    }


    @Override
    public void addPostConstructMethod(String clazz, String method) {
        if (clazz == null || method == null)
            throw new IllegalArgumentException(
                    sm.getString("standardContext.postconstruct.required"));
        if (postConstructMethods.get(clazz) != null)
            throw new IllegalArgumentException(sm.getString(
                    "standardContext.postconstruct.duplicate", clazz));

        postConstructMethods.put(clazz, method);
        fireContainerEvent("addPostConstructMethod", clazz);
    }


    @Override
    public void removePostConstructMethod(String clazz) {
        postConstructMethods.remove(clazz);
        fireContainerEvent("removePostConstructMethod", clazz);
    }


    @Override
    public void addPreDestroyMethod(String clazz, String method) {
        if (clazz == null || method == null)
            throw new IllegalArgumentException(
                    sm.getString("standardContext.predestroy.required"));
        if (preDestroyMethods.get(clazz) != null)
            throw new IllegalArgumentException(sm.getString(
                    "standardContext.predestroy.duplicate", clazz));

        preDestroyMethods.put(clazz, method);
        fireContainerEvent("addPreDestroyMethod", clazz);
    }


    @Override
    public void removePreDestroyMethod(String clazz) {
        preDestroyMethods.remove(clazz);
        fireContainerEvent("removePreDestroyMethod", clazz);
    }


    @Override
    public String findPostConstructMethod(String clazz) {
        return postConstructMethods.get(clazz);
    }


    @Override
    public String findPreDestroyMethod(String clazz) {
        return preDestroyMethods.get(clazz);
    }


    @Override
    public Map<String, String> findPostConstructMethods() {
        return postConstructMethods;
    }


    @Override
    public Map<String, String> findPreDestroyMethods() {
        return preDestroyMethods;
    }

    private void postWorkDirectory() {

        // Acquire (or calculate) the work directory path
        String workDir = getWorkDir();
        if (workDir == null || workDir.length() == 0) {

            // Retrieve our parent (normally a host) name
            String hostName = null;
            String engineName = null;
            String hostWorkDir = null;
            Container parentHost = getParent();
            if (parentHost != null) {
                hostName = parentHost.getName();
                if (parentHost instanceof StandardHost) {
                    hostWorkDir = ((StandardHost)parentHost).getWorkDir();
                }
                Container parentEngine = parentHost.getParent();
                if (parentEngine != null) {
                   engineName = parentEngine.getName();
                }
            }
            if ((hostName == null) || (hostName.length() < 1))
                hostName = "_";
            if ((engineName == null) || (engineName.length() < 1))
                engineName = "_";

            String temp = getBaseName();
            if (temp.startsWith("/"))
                temp = temp.substring(1);
            temp = temp.replace('/', '_');
            temp = temp.replace('\\', '_');
            if (temp.length() < 1)
                temp = ContextName.ROOT_NAME;
            if (hostWorkDir != null ) {
                workDir = hostWorkDir + File.separator + temp;
            } else {
                workDir = "work" + File.separator + engineName +
                    File.separator + hostName + File.separator + temp;
            }
            setWorkDir(workDir);
        }

        // Create this directory if necessary
        File dir = new File(workDir);
        if (!dir.isAbsolute()) {
            String catalinaHomePath = null;
            try {
                catalinaHomePath = getCatalinaBase().getCanonicalPath();
                dir = new File(catalinaHomePath, workDir);
            } catch (IOException e) {
                log.warn(sm.getString("standardContext.workCreateException",
                        workDir, catalinaHomePath, getName()), e);
            }
        }
        if (!dir.mkdirs() && !dir.isDirectory()) {
            log.warn(sm.getString("standardContext.workCreateFail", dir,
                    getName()));
        }

        // Set the appropriate servlet context attribute
        if (context == null) {
            getServletContext();
        }
        context.setAttribute(ServletContext.TEMPDIR, dir);
        context.setAttributeReadOnly(ServletContext.TEMPDIR);
    }

    private void setPaused(boolean paused) {
        this.paused = paused;
    }

    private boolean validateURLPattern(String urlPattern) {
        if (urlPattern == null)
            return (false);
        if (urlPattern.indexOf('\n') >= 0 || urlPattern.indexOf('\r') >= 0) {
            return (false);
        }
        if (urlPattern.equals("")) {
            return true;
        }
        if (urlPattern.startsWith("*.")) {
            if (urlPattern.indexOf('/') < 0) {
                checkUnusualURLPattern(urlPattern);
                return (true);
            } else
                return (false);
        }
        if ( (urlPattern.startsWith("/")) &&
                (urlPattern.indexOf("*.") < 0)) {
            checkUnusualURLPattern(urlPattern);
            return (true);
        } else
            return (false);
    }

    private void checkUnusualURLPattern(String urlPattern) {
        if (log.isInfoEnabled()) {
            // First group checks for '*' or '/foo*' style patterns
            // Second group checks for *.foo.bar style patterns
            if((urlPattern.endsWith("*") && (urlPattern.length() < 2 ||
                        urlPattern.charAt(urlPattern.length()-2) != '/')) ||
                    urlPattern.startsWith("*.") && urlPattern.length() > 2 &&
                        urlPattern.lastIndexOf('.') > 1) {
                log.info("Suspicious url pattern: \"" + urlPattern + "\"" +
                        " in context [" + getName() + "] - see" +
                        " sections 12.1 and 12.2 of the Servlet specification");
            }
        }
    }


    // ------------------------------------------------------------- Operations


    @Deprecated
    public String getDeploymentDescriptor() {
        InputStream stream = null;
        ServletContext servletContext = getServletContext();
        if (servletContext != null) {
            stream = servletContext.getResourceAsStream(
                org.apache.catalina.startup.Constants.ApplicationWebXml);
        }
        if (stream == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(stream))) {
            String strRead = "";
            while (strRead != null) {
                sb.append(strRead);
                strRead = br.readLine();
            }
        } catch (IOException e) {
            return "";
        }
        return sb.toString();
    }

    @Deprecated
    public String[] getServlets() {
        String[] result = null;
        Container[] children = findChildren();
        if (children != null) {
            result = new String[children.length];
            for( int i=0; i< children.length; i++ ) {
                result[i] = children[i].getObjectName().toString();
            }
        }
        return result;
    }

    @Override
    protected String getObjectNameKeyProperties() {
        StringBuilder keyProperties =
            new StringBuilder("j2eeType=WebModule,");
        keyProperties.append(getObjectKeyPropertiesNameOnly());
        keyProperties.append(",J2EEApplication=");
        keyProperties.append(getJ2EEApplication());
        keyProperties.append(",J2EEServer=");
        keyProperties.append(getJ2EEServer());
        return keyProperties.toString();
    }

    private String getObjectKeyPropertiesNameOnly() {
        StringBuilder result = new StringBuilder("name=//");
        String hostname = getParent().getName();
        if (hostname == null) {
            result.append("DEFAULT");
        } else {
            result.append(hostname);
        }
        String contextName = getName();
        if (!contextName.startsWith("/")) {
            result.append('/');
        }
        result.append(contextName);
        return result.toString();
    }

    @Override
    protected void initInternal() throws LifecycleException {
        super.initInternal();
        // Register the naming resources
        if (namingResources != null) {
            namingResources.init();
        }
        // Send j2ee.object.created notification
        if (this.getObjectName() != null) {
            Notification notification = new Notification("j2ee.object.created",
                    this.getObjectName(), sequenceNumber.getAndIncrement());
            broadcaster.sendNotification(notification);
        }
    }

    @Override
    public void removeNotificationListener(NotificationListener listener,
            NotificationFilter filter, Object object) throws ListenerNotFoundException {
        broadcaster.removeNotificationListener(listener,filter,object);
    }

    private MBeanNotificationInfo[] notificationInfo;

    @Override
    public MBeanNotificationInfo[] getNotificationInfo() {
        // FIXME: i18n
        if(notificationInfo == null) {
            notificationInfo = new MBeanNotificationInfo[]{
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.object.created"},
                    Notification.class.getName(),
                    "web application is created"
                    ),
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.state.starting"},
                    Notification.class.getName(),
                    "change web application is starting"
                    ),
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.state.running"},
                    Notification.class.getName(),
                    "web application is running"
                    ),
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.state.stopping"},
                    Notification.class.getName(),
                    "web application start to stopped"
                    ),
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.object.stopped"},
                    Notification.class.getName(),
                    "web application is stopped"
                    ),
                    new MBeanNotificationInfo(new String[] {
                    "j2ee.object.deleted"},
                    Notification.class.getName(),
                    "web application is deleted"
                    )
            };
        }
        return notificationInfo;
    }

    @Override
    public void addNotificationListener(NotificationListener listener,
            NotificationFilter filter, Object object) throws IllegalArgumentException {
        broadcaster.addNotificationListener(listener,filter,object);
    }

    @Override
    public void removeNotificationListener(NotificationListener listener)
    throws ListenerNotFoundException {
        broadcaster.removeNotificationListener(listener);
    }

    // ------------------------------------------------------------- Attributes


    public String[] getWelcomeFiles() {
        return findWelcomeFiles();
    }

    @Override
    public boolean getXmlNamespaceAware() {
        return webXmlNamespaceAware;
    }

    @Override
    public void setXmlNamespaceAware(boolean webXmlNamespaceAware) {
        this.webXmlNamespaceAware = webXmlNamespaceAware;
    }

    @Override
    public void setXmlValidation(boolean webXmlValidation) {
        this.webXmlValidation = webXmlValidation;
    }

    @Override
    public boolean getXmlValidation() {
        return webXmlValidation;
    }

    @Override
    public void setXmlBlockExternal(boolean xmlBlockExternal) {
        this.xmlBlockExternal = xmlBlockExternal;
    }

    @Override
    public boolean getXmlBlockExternal() {
        return xmlBlockExternal;
    }

    @Override
    public void setTldValidation(boolean tldValidation) {
        this.tldValidation = tldValidation;
    }

    @Override
    public boolean getTldValidation() {
        return tldValidation;
    }

    @Deprecated
    public boolean isStateManageable() {
        return true;
    }

    private String server = null;

    private String[] javaVMs = null;

    public String getServer() {
        return server;
    }

    public String setServer(String server) {
        return this.server=server;
    }

    public String[] getJavaVMs() {
        return javaVMs;
    }

    public String[] setJavaVMs(String[] javaVMs) {
        return this.javaVMs = javaVMs;
    }

    public long getStartTime() {
        return startTime;
    }

    private static class NoPluggabilityServletContext
            implements ServletContext {
        private final ServletContext sc;
        public NoPluggabilityServletContext(ServletContext sc) {
            this.sc = sc;
        }
        @Override
        public String getContextPath() {
            return sc.getContextPath();
        }
        @Override
        public ServletContext getContext(String uripath) {
            return sc.getContext(uripath);
        }
        @Override
        public int getMajorVersion() {
           return sc.getMajorVersion();
        }
        @Override
        public int getMinorVersion() {
            return sc.getMinorVersion();
        }
        @Override
        public int getEffectiveMajorVersion() {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public int getEffectiveMinorVersion() {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public String getMimeType(String file) {
            return sc.getMimeType(file);
        }
        @Override
        public Set<String> getResourcePaths(String path) {
            return sc.getResourcePaths(path);
        }
        @Override
        public URL getResource(String path) throws MalformedURLException {
            return sc.getResource(path);
        }
        @Override
        public InputStream getResourceAsStream(String path) {
            return sc.getResourceAsStream(path);
        }
        @Override
        public RequestDispatcher getRequestDispatcher(String path) {
            return sc.getRequestDispatcher(path);
        }
        @Override
        public RequestDispatcher getNamedDispatcher(String name) {
            return sc.getNamedDispatcher(name);
        }
        @Override
        @Deprecated
        public Servlet getServlet(String name) throws ServletException {
            return sc.getServlet(name);
        }
        @Override
        @Deprecated
        public Enumeration<Servlet> getServlets() {
            return sc.getServlets();
        }
        @Override
        @Deprecated
        public Enumeration<String> getServletNames() {
            return sc.getServletNames();
        }
        @Override
        public void log(String msg) {
            sc.log(msg);
        }
        @Override
        @Deprecated
        public void log(Exception exception, String msg) {
            sc.log(exception, msg);
        }
        @Override
        public void log(String message, Throwable throwable) {
            sc.log(message, throwable);
        }
        @Override
        public String getRealPath(String path) {
            return sc.getRealPath(path);
        }
        @Override
        public String getServerInfo() {
            return sc.getServerInfo();
        }
        @Override
        public String getInitParameter(String name) {
            return sc.getInitParameter(name);
        }
        @Override
        public Enumeration<String> getInitParameterNames() {
            return sc.getInitParameterNames();
        }
        @Override
        public boolean setInitParameter(String name, String value) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public Object getAttribute(String name) {
            return sc.getAttribute(name);
        }
        @Override
        public Enumeration<String> getAttributeNames() {
            return sc.getAttributeNames();
        }
        @Override
        public void setAttribute(String name, Object object) {
            sc.setAttribute(name, object);
        }
        @Override
        public void removeAttribute(String name) {
            sc.removeAttribute(name);
        }
        @Override
        public String getServletContextName() {
            return sc.getServletContextName();
        }
        @Override
        public Dynamic addServlet(String servletName, String className) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public Dynamic addServlet(String servletName, Servlet servlet) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public Dynamic addServlet(String servletName,
                Class<? extends Servlet> servletClass) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public <T extends Servlet> T createServlet(Class<T> c)
                throws ServletException {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public ServletRegistration getServletRegistration(String servletName) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public Map<String,? extends ServletRegistration> getServletRegistrations() {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public javax.servlet.FilterRegistration.Dynamic addFilter(
                String filterName, String className) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public javax.servlet.FilterRegistration.Dynamic addFilter(
                String filterName, Filter filter) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public javax.servlet.FilterRegistration.Dynamic addFilter(
                String filterName, Class<? extends Filter> filterClass) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public <T extends Filter> T createFilter(Class<T> c)
                throws ServletException {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public FilterRegistration getFilterRegistration(String filterName) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public Map<String,? extends FilterRegistration> getFilterRegistrations() {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public SessionCookieConfig getSessionCookieConfig() {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public void setSessionTrackingModes(
                Set<SessionTrackingMode> sessionTrackingModes) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public Set<SessionTrackingMode> getDefaultSessionTrackingModes() {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public Set<SessionTrackingMode> getEffectiveSessionTrackingModes() {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public void addListener(String className) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public <T extends EventListener> void addListener(T t) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public void addListener(Class<? extends EventListener> listenerClass) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public <T extends EventListener> T createListener(Class<T> c)
                throws ServletException {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public JspConfigDescriptor getJspConfigDescriptor() {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public ClassLoader getClassLoader() {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public void declareRoles(String... roleNames) {
            throw new UnsupportedOperationException(
                    sm.getString("noPluggabilityServletContext.notAllowed"));
        }
        @Override
        public String getVirtualServerName() {
            return sc.getVirtualServerName();
        }
    }
}
