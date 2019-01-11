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


package org.apache.tomcat.util.modeler;


import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.net.URL;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

import javax.management.DynamicMBean;
import javax.management.MBeanAttributeInfo;
import javax.management.MBeanInfo;
import javax.management.MBeanOperationInfo;
import javax.management.MBeanRegistration;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.modeler.modules.ModelerSource;

/*
   Issues:
   - exceptions - too many "throws Exception"
   - double check the interfaces
   - start removing the use of the experimental methods in tomcat, then remove
     the methods ( before 1.1 final )
   - is the security enough to prevent Registry being used to avoid the permission
    checks in the mbean server ?
*/

/**
 * JMX中MBena的注册管理类
 * Registry for modeler MBeans.
 *
 * This is the main entry point into modeler. It provides methods to create
 * and manipulate model mbeans and simplify their use.
 *
 * @author Craig R. McClanahan
 * @author Costin Manolache
 */
public class Registry implements RegistryMBean, MBeanRegistration  {

    private static final Log log = LogFactory.getLog(Registry.class);

    /**
     * 根据对象获取Registry
     */
    private static final HashMap<Object,Registry> perLoaderRegistries = null;

    //工厂方法创建实例对象
    private static Registry registry = null;

    //成员属性,负责注册,注销MBean对象
    private MBeanServer server = null;

    /**
	 * 对每个MBean的描述,存储注册的MBean
     */
    private HashMap<String,ManagedBean> descriptors = new HashMap<>();

    /** 
     * 对每个MBean的描述,键是类名
     */
    private HashMap<String,ManagedBean> descriptorsByClass = new HashMap<>();


    private HashMap<String,URL> searchedPaths = new HashMap<>();

    private Object guard;

    private final Hashtable<String,Hashtable<String,Integer>> idDomains =
        new Hashtable<>();
    private final Hashtable<String,int[]> ids = new Hashtable<>();

     public Registry() {
        super();
    }

    /**
     * tomcat在调用这个方法的时候传入的参数是两个null,
     * 工厂方法,根据key获取Registry,没有就新建一个
     */
    public static synchronized Registry getRegistry(Object key, Object guard) {
        Registry localRegistry;
        if( perLoaderRegistries!=null ) {
            if( key==null )
                key=Thread.currentThread().getContextClassLoader();
            if( key != null ) {
                localRegistry = perLoaderRegistries.get(key);
                if( localRegistry == null ) {
                    localRegistry=new Registry();
                    localRegistry.guard=guard;
                    //放入缓存
                    perLoaderRegistries.put( key, localRegistry );
                    return localRegistry;
                }
                if( localRegistry.guard != null &&
                        localRegistry.guard != guard ) {
                    return null; // XXX Should I throw a permission ex ?
                }
                return localRegistry;
            }
        }

        // 实力化registry对象,注意register是一个static修饰的对象
        if (registry == null) {
            registry = new Registry();
        }
        if( registry.guard != null &&
                registry.guard != guard ) {
            return null;
        }
        return (registry);
    }

 
    /** Lifecycle method - clean up the registry metadata.
     *  Called from resetMetadata().
     */
    @Override
    public void stop() {
        descriptorsByClass = new HashMap<>();
        descriptors = new HashMap<>();
        searchedPaths=new HashMap<>();
    }

    /**
     * 注册一个MBean,通过创建一个 modeler mbean实现注册,并且添加到MBeanServer
     */
    @Override
    public void registerComponent(Object bean, String oname, String type)
           throws Exception
    {
        registerComponent(bean, new ObjectName(oname), type);
    }

    /** 
     * 销毁一个MBean
     */
    @Override
    public void unregisterComponent( String oname ) {
        try {
            unregisterComponent(new ObjectName(oname));
        } catch (MalformedObjectNameException e) {
            log.info("Error creating object name " + e );
        }
    }


    /** 
     * 调用MBean中的方法operation
     * @since 1.1
     */
    @Override
    public void invoke(List<ObjectName> mbeans, String operation,
            boolean failFirst ) throws Exception {
        if( mbeans==null ) {
            return;
        }
        Iterator<ObjectName> itr = mbeans.iterator();
        while(itr.hasNext()) {
            ObjectName current = itr.next();
            try {
                if(current == null) {
                    continue;
                }
                if(getMethodInfo(current, operation) == null) {
                    continue;
                }
                getMBeanServer().invoke(current, operation,
                        new Object[] {}, new String[] {});

            } catch( Exception t ) {
                if( failFirst ) throw t;
                log.info("Error initializing " + current + " " + t.toString());
            }
        }
    }

    // -------------------- ID registry --------------------

    /** Return an int ID for faster access. Will be used for notifications
     * and for other operations we want to optimize.
     *
     * @param domain Namespace
     * @param name  Type of the notification
     * @return  An unique id for the domain:name combination
     * @since 1.1
     */
    @Override
    public synchronized int getId( String domain, String name) {
        if( domain==null) {
            domain="";
        }
        Hashtable<String,Integer> domainTable = idDomains.get(domain);
        if( domainTable == null ) {
            domainTable = new Hashtable<>();
            idDomains.put( domain, domainTable);
        }
        if( name==null ) {
            name="";
        }
        Integer i = domainTable.get(name);

        if( i!= null ) {
            return i.intValue();
        }

        int id[] = ids.get(domain);
        if( id == null ) {
            id=new int[1];
            ids.put( domain, id);
        }
        int code=id[0]++;
        domainTable.put( name, Integer.valueOf( code ));
        return code;
    }

    // -------------------- Metadata   --------------------
    // methods from 1.0

    /**
     * 将创建的ManagedMBean放入map中
     */
    public void addManagedBean(ManagedBean bean) {
        // XXX Use group + name
        descriptors.put(bean.getName(), bean);
        if( bean.getType() != null ) {
            descriptorsByClass.put( bean.getType(), bean );
        }
    }


    /**
     * 从两个map中搜索对象,相当于从缓存中搜索
     */
    public ManagedBean findManagedBean(String name) {
        // XXX Group ?? Use Group + Type
        ManagedBean mb = descriptors.get(name);
        if( mb==null )
            mb = descriptorsByClass.get(name);
        return mb;
    }

    // -------------------- Helpers  --------------------

    /** Get the type of an attribute of the object, from the metadata.
     *
     * @param oname
     * @param attName
     * @return null if metadata about the attribute is not found
     * @since 1.1
     */
    public String getType( ObjectName oname, String attName )
    {
        String type=null;
        MBeanInfo info=null;
        try {
            info=server.getMBeanInfo(oname);
        } catch (Exception e) {
            log.info( "Can't find metadata for object" + oname );
            return null;
        }

        MBeanAttributeInfo attInfo[]=info.getAttributes();
        for( int i=0; i<attInfo.length; i++ ) {
            if( attName.equals(attInfo[i].getName())) {
                type=attInfo[i].getType();
                return type;
            }
        }
        return null;
    }

    /** Find the operation info for a method
     *
     * @param oname
     * @param opName
     * @return the operation info for the specified operation
     */
    public MBeanOperationInfo getMethodInfo( ObjectName oname, String opName )
    {
        MBeanInfo info=null;
        try {
            info=server.getMBeanInfo(oname);
        } catch (Exception e) {
            log.info( "Can't find metadata " + oname );
            return null;
        }
        MBeanOperationInfo attInfo[]=info.getOperations();
        for( int i=0; i<attInfo.length; i++ ) {
            if( opName.equals(attInfo[i].getName())) {
                return attInfo[i];
            }
        }
        return null;
    }

    
    public void unregisterComponent( ObjectName oname ) {
        try {
            if( getMBeanServer().isRegistered(oname)) {
                getMBeanServer().unregisterMBean(oname);
            }
        } catch( Throwable t ) {
            log.error( "Error unregistering mbean ", t);
        }
    }

    /**
     * 工厂方法创建MBeanServer
     */
    public synchronized MBeanServer getMBeanServer() {
        long t1=System.currentTimeMillis();

        if (server == null) {
        	//通过MBeanServerFactory.getPlatformMBeanServer();生成server对象
            if( MBeanServerFactory.findMBeanServer(null).size() > 0 ) {
                server = MBeanServerFactory.findMBeanServer(null).get(0);
                if( log.isDebugEnabled() ) {
                    log.debug("Using existing MBeanServer " + (System.currentTimeMillis() - t1 ));
                }
            } else {
                server = ManagementFactory.getPlatformMBeanServer();
                if( log.isDebugEnabled() ) {
                    log.debug("Creating MBeanServer"+ (System.currentTimeMillis() - t1 ));
                }
            }
        }
        return (server);
    }

    /** 从缓存中查找MBean,如果没有则直接根据xml配置文件创建
     */
    public ManagedBean findManagedBean(Object bean, Class<?> beanClass,
            String type) throws Exception {
        if( bean!=null && beanClass==null ) {
            beanClass=bean.getClass();
        }

        if( type==null ) {
            type=beanClass.getName();
        }

        // 首先从缓存descriptor中查找MBean
        ManagedBean managed = findManagedBean(type);

        // 如果缓存中没有找到
        if( managed==null ) {
            // check package and parent packages
            if( log.isDebugEnabled() ) {
                log.debug( "Looking for descriptor ");
            }
            //通过配置文件生成MBean对象
            findDescriptor( beanClass, type );
            //再次从缓存中搜索
            managed=findManagedBean(type);
        }

        // 仍然没找到则通过introspection(内省)
        if( managed==null ) {
            if( log.isDebugEnabled() ) {
                log.debug( "Introspecting ");
            }

            // 内省方式创建对象
            load("MbeansDescriptorsIntrospectionSource", beanClass, type);
            //再次搜索
            managed=findManagedBean(type);
            if( managed==null ) {
                log.warn( "No metadata found for " + type );
                return null;
            }
            managed.setName( type );
            addManagedBean(managed);
        }
        return managed;
    }


    /** EXPERIMENTAL Convert a string to object, based on type. Used by several
     * components. We could provide some pluggability. It is here to keep
     * things consistent and avoid duplication in other tasks
     *
     * @param type Fully qualified class name of the resulting value
     * @param value String value to be converted
     * @return Converted value
     */
    public Object convertValue(String type, String value)
    {
        Object objValue=value;

        if( type==null || "java.lang.String".equals( type )) {
            // string is default
            objValue=value;
        } else if( "javax.management.ObjectName".equals( type ) ||
                "ObjectName".equals( type )) {
            try {
                objValue=new ObjectName( value );
            } catch (MalformedObjectNameException e) {
                return null;
            }
        } else if( "java.lang.Integer".equals( type ) ||
                "int".equals( type )) {
            objValue=Integer.valueOf( value );
        } else if( "java.lang.Long".equals( type ) ||
                "long".equals( type )) {
            objValue=Long.valueOf( value );
        } else if( "java.lang.Boolean".equals( type ) ||
                "boolean".equals( type )) {
            objValue=Boolean.valueOf( value );
        }
        return objValue;
    }

    /**最终是通过org.apache.tomcat.util.modeler.modules下的工具类来解析xml文件创建对象或者通过内省的方式创建对象
     * 根据sourceType的值判断通过哪种方式创建对象,MbeansDescriptorsIntrospectionSource和MbeansDescriptorsDigesterSource两种
     * @param sourceType
     * @param source 一般是URL,File,InputStream,Class等类型
     * @param param
     * @return List of descriptors
     * @throws Exception
     */
    public List<ObjectName> load( String sourceType, Object source,
            String param) throws Exception {
        if( log.isTraceEnabled()) {
            log.trace("load " + source );
        }
        String location=null;
        String type=null;
        Object inputsource=null;
        //将参数source转换为相应的类型
        if( source instanceof URL ) {
            URL url=(URL)source;
            location=url.toString();
            type=param;
            inputsource=url.openStream();
            //通过digestr创建对象
            if (sourceType == null && location.endsWith(".xml")) {
                sourceType = "MbeansDescriptorsDigesterSource";
            }
        } else if( source instanceof File ) {
            location=((File)source).getAbsolutePath();
            inputsource=new FileInputStream((File)source);
            type=param;
            //通过内省的方式创建对象
            if (sourceType == null && location.endsWith(".xml")) {
                sourceType = "MbeansDescriptorsDigesterSource";
            }
        } else if( source instanceof InputStream ) {
            type=param;
            inputsource=source;
        } else if( source instanceof Class<?> ) {
            location=((Class<?>)source).getName();
            type=param;
            inputsource=source;
            //通过内省的方式创建对象
            if( sourceType== null ) {
                sourceType="MbeansDescriptorsIntrospectionSource";
            }
        }
        //默认是通过digester的方式创建对象
        if( sourceType==null ) {
            sourceType="MbeansDescriptorsDigesterSource";
        }
        ModelerSource ds=getModelerSource(sourceType);
        //通过ds对象创建一系列对象
        List<ObjectName> mbeans =
            ds.loadDescriptors(this, type, inputsource);

        return mbeans;
    }


   
    public void registerComponent(Object bean, ObjectName oname, String type)
           throws Exception
    {
        if( log.isDebugEnabled() ) {
            log.debug( "Managed= "+ oname);
        }
        //如果要注册的对象为null则直接返回
        if( bean ==null ) {
            log.error("Null component " + oname );
            return;
        }

        try {
        	//获取全类名
            if( type==null ) {
                type=bean.getClass().getName();
            }
            //从缓存中查找
            ManagedBean managed = findManagedBean(null, bean.getClass(), type);

            //通过ManagedBean创建MBean对象,实际创建的对象是BaseModelMBean类型的,他实现了java.managed包中的几个接口
            DynamicMBean mbean = managed.createMBean(bean);
            //如果已经注册MBean
            if(  getMBeanServer().isRegistered( oname )) {
                if( log.isDebugEnabled()) {
                    log.debug("Unregistering existing component " + oname );
                }
                //取消注册
                getMBeanServer().unregisterMBean( oname );
            }
            //注册MBean
            getMBeanServer().registerMBean( mbean, oname);
        } catch( Exception ex) {
            log.error("Error registering " + oname, ex );
            throw ex;
        }
    }


    /**
     * 通过类加载器加载相应包中的mbeans-descriptors.xml文件,供解析使用
     * @param packageName
     * @param classLoader
     */
    public void loadDescriptors( String packageName, ClassLoader classLoader  ) {
        String res=packageName.replace( '.', '/');

        if( log.isTraceEnabled() ) {
            log.trace("Finding descriptor " + res );
        }
        //如果已经加载过
        if( searchedPaths.get( packageName ) != null ) {
            return;
        }

        String descriptors = res + "/mbeans-descriptors.xml";
        URL dURL = classLoader.getResource( descriptors );

        if (dURL == null) {
            return;
        }

        log.debug( "Found " + dURL);
        //把加载过的路径放入map中
        searchedPaths.put( packageName,  dURL );
        try {
            load("MbeansDescriptorsDigesterSource", dURL, null);
        } catch(Exception ex ) {
            log.error("Error loading " + dURL);
        }
    }

    /**
     * 通过xml配置文件实例化该beanClass,查找并解析beanClass这个类的包中的mbeans-descriptors.xml来创建MBean对象
     * @param beanClass
     * @param type
     */
    private void findDescriptor(Class<?> beanClass, String type) {
        if( type==null ) {
            type=beanClass.getName();
        }
        ClassLoader classLoader=null;
        if( beanClass!=null ) {
            classLoader=beanClass.getClassLoader();
        }
        if( classLoader==null ) {
            classLoader=Thread.currentThread().getContextClassLoader();
        }
        if( classLoader==null ) {
            classLoader=this.getClass().getClassLoader();
        }

        String className=type;
        String pkg=className;
        while( pkg.indexOf( ".") > 0 ) {
            int lastComp=pkg.lastIndexOf( ".");
            if( lastComp <= 0 ) return;
            pkg=pkg.substring(0, lastComp);
            if( searchedPaths.get( pkg ) != null ) {
                return;
            }
            loadDescriptors(pkg, classLoader);
        }
        return;
    }

    /**
     * 通过反射构造org.apache.tomcat.util.modeler.modules包中的对象
     * 包中的类主要是创建digester对象,提供解析xml文件的功能,并且将创建的对象
     * 通过addMBean方法添加到descriptorsByClass这个map中
     * @param type
     * @return
     * @throws Exception
     */
    private ModelerSource getModelerSource( String type )
            throws Exception
    {
        if( type==null ) type="MbeansDescriptorsDigesterSource";
        if( type.indexOf( ".") < 0 ) {
            type="org.apache.tomcat.util.modeler.modules." + type;
        }
        //加载字节码
        Class<?> c = Class.forName(type);
        //通过反射构造一个对象
        ModelerSource ds=(ModelerSource)c.getConstructor().newInstance();
        return ds;
    }


    // -------------------- Registration  --------------------

    @Override
    public ObjectName preRegister(MBeanServer server,
                                  ObjectName name) throws Exception
    {
        this.server=server;
        return name;
    }

    @Override
    public void postRegister(Boolean registrationDone) {
    }

    @Override
    public void preDeregister() throws Exception {
    }

    @Override
    public void postDeregister() {
    }
}
