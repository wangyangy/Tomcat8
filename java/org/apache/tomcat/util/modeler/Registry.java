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
 * JMX��MBena��ע�������
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
     * ���ݶ����ȡRegistry
     */
    private static final HashMap<Object,Registry> perLoaderRegistries = null;

    //������������ʵ������
    private static Registry registry = null;

    //��Ա����,����ע��,ע��MBean����
    private MBeanServer server = null;

    /**
	 * ��ÿ��MBean������,�洢ע���MBean
     */
    private HashMap<String,ManagedBean> descriptors = new HashMap<>();

    /** 
     * ��ÿ��MBean������,��������
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
     * tomcat�ڵ������������ʱ����Ĳ���������null,
     * ��������,����key��ȡRegistry,û�о��½�һ��
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
                    //���뻺��
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

        // ʵ����registry����,ע��register��һ��static���εĶ���
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
     * ע��һ��MBean,ͨ������һ�� modeler mbeanʵ��ע��,������ӵ�MBeanServer
     */
    @Override
    public void registerComponent(Object bean, String oname, String type)
           throws Exception
    {
        registerComponent(bean, new ObjectName(oname), type);
    }

    /** 
     * ����һ��MBean
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
     * ����MBean�еķ���operation
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
     * ��������ManagedMBean����map��
     */
    public void addManagedBean(ManagedBean bean) {
        // XXX Use group + name
        descriptors.put(bean.getName(), bean);
        if( bean.getType() != null ) {
            descriptorsByClass.put( bean.getType(), bean );
        }
    }


    /**
     * ������map����������,�൱�ڴӻ���������
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
     * ������������MBeanServer
     */
    public synchronized MBeanServer getMBeanServer() {
        long t1=System.currentTimeMillis();

        if (server == null) {
        	//ͨ��MBeanServerFactory.getPlatformMBeanServer();����server����
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

    /** �ӻ����в���MBean,���û����ֱ�Ӹ���xml�����ļ�����
     */
    public ManagedBean findManagedBean(Object bean, Class<?> beanClass,
            String type) throws Exception {
        if( bean!=null && beanClass==null ) {
            beanClass=bean.getClass();
        }

        if( type==null ) {
            type=beanClass.getName();
        }

        // ���ȴӻ���descriptor�в���MBean
        ManagedBean managed = findManagedBean(type);

        // ���������û���ҵ�
        if( managed==null ) {
            // check package and parent packages
            if( log.isDebugEnabled() ) {
                log.debug( "Looking for descriptor ");
            }
            //ͨ�������ļ�����MBean����
            findDescriptor( beanClass, type );
            //�ٴδӻ���������
            managed=findManagedBean(type);
        }

        // ��Ȼû�ҵ���ͨ��introspection(��ʡ)
        if( managed==null ) {
            if( log.isDebugEnabled() ) {
                log.debug( "Introspecting ");
            }

            // ��ʡ��ʽ��������
            load("MbeansDescriptorsIntrospectionSource", beanClass, type);
            //�ٴ�����
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

    /**������ͨ��org.apache.tomcat.util.modeler.modules�µĹ�����������xml�ļ������������ͨ����ʡ�ķ�ʽ��������
     * ����sourceType��ֵ�ж�ͨ�����ַ�ʽ��������,MbeansDescriptorsIntrospectionSource��MbeansDescriptorsDigesterSource����
     * @param sourceType
     * @param source һ����URL,File,InputStream,Class������
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
        //������sourceת��Ϊ��Ӧ������
        if( source instanceof URL ) {
            URL url=(URL)source;
            location=url.toString();
            type=param;
            inputsource=url.openStream();
            //ͨ��digestr��������
            if (sourceType == null && location.endsWith(".xml")) {
                sourceType = "MbeansDescriptorsDigesterSource";
            }
        } else if( source instanceof File ) {
            location=((File)source).getAbsolutePath();
            inputsource=new FileInputStream((File)source);
            type=param;
            //ͨ����ʡ�ķ�ʽ��������
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
            //ͨ����ʡ�ķ�ʽ��������
            if( sourceType== null ) {
                sourceType="MbeansDescriptorsIntrospectionSource";
            }
        }
        //Ĭ����ͨ��digester�ķ�ʽ��������
        if( sourceType==null ) {
            sourceType="MbeansDescriptorsDigesterSource";
        }
        ModelerSource ds=getModelerSource(sourceType);
        //ͨ��ds���󴴽�һϵ�ж���
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
        //���Ҫע��Ķ���Ϊnull��ֱ�ӷ���
        if( bean ==null ) {
            log.error("Null component " + oname );
            return;
        }

        try {
        	//��ȡȫ����
            if( type==null ) {
                type=bean.getClass().getName();
            }
            //�ӻ����в���
            ManagedBean managed = findManagedBean(null, bean.getClass(), type);

            //ͨ��ManagedBean����MBean����,ʵ�ʴ����Ķ�����BaseModelMBean���͵�,��ʵ����java.managed���еļ����ӿ�
            DynamicMBean mbean = managed.createMBean(bean);
            //����Ѿ�ע��MBean
            if(  getMBeanServer().isRegistered( oname )) {
                if( log.isDebugEnabled()) {
                    log.debug("Unregistering existing component " + oname );
                }
                //ȡ��ע��
                getMBeanServer().unregisterMBean( oname );
            }
            //ע��MBean
            getMBeanServer().registerMBean( mbean, oname);
        } catch( Exception ex) {
            log.error("Error registering " + oname, ex );
            throw ex;
        }
    }


    /**
     * ͨ���������������Ӧ���е�mbeans-descriptors.xml�ļ�,������ʹ��
     * @param packageName
     * @param classLoader
     */
    public void loadDescriptors( String packageName, ClassLoader classLoader  ) {
        String res=packageName.replace( '.', '/');

        if( log.isTraceEnabled() ) {
            log.trace("Finding descriptor " + res );
        }
        //����Ѿ����ع�
        if( searchedPaths.get( packageName ) != null ) {
            return;
        }

        String descriptors = res + "/mbeans-descriptors.xml";
        URL dURL = classLoader.getResource( descriptors );

        if (dURL == null) {
            return;
        }

        log.debug( "Found " + dURL);
        //�Ѽ��ع���·������map��
        searchedPaths.put( packageName,  dURL );
        try {
            load("MbeansDescriptorsDigesterSource", dURL, null);
        } catch(Exception ex ) {
            log.error("Error loading " + dURL);
        }
    }

    /**
     * ͨ��xml�����ļ�ʵ������beanClass,���Ҳ�����beanClass�����İ��е�mbeans-descriptors.xml������MBean����
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
     * ͨ�����乹��org.apache.tomcat.util.modeler.modules���еĶ���
     * ���е�����Ҫ�Ǵ���digester����,�ṩ����xml�ļ��Ĺ���,���ҽ������Ķ���
     * ͨ��addMBean������ӵ�descriptorsByClass���map��
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
        //�����ֽ���
        Class<?> c = Class.forName(type);
        //ͨ�����乹��һ������
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
