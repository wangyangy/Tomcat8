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


import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.management.AttributeNotFoundException;
import javax.management.DynamicMBean;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanAttributeInfo;
import javax.management.MBeanConstructorInfo;
import javax.management.MBeanException;
import javax.management.MBeanInfo;
import javax.management.MBeanNotificationInfo;
import javax.management.MBeanOperationInfo;
import javax.management.ReflectionException;
import javax.management.RuntimeOperationsException;
import javax.management.ServiceNotFoundException;


/**该类类似于一个MBean对象的包装类
 * <p>Internal configuration information for a managed bean (MBean)
 * descriptor.</p>
 *
 * @author Craig R. McClanahan
 */
public class ManagedBean implements java.io.Serializable {

    private static final long serialVersionUID = 1L;

    private static final String BASE_MBEAN = "org.apache.tomcat.util.modeler.BaseModelMBean";
    // ----------------------------------------------------- Instance Variables
    static final Class<?>[] NO_ARGS_PARAM_SIG = new Class[0];


    private final ReadWriteLock mBeanInfoLock = new ReentrantReadWriteLock();
    /**
     * The <code>ModelMBeanInfo</code> object that corresponds
     * to this <code>ManagedBean</code> instance.
     */
    private transient volatile MBeanInfo info = null;

    //存放属性
    private Map<String,AttributeInfo> attributes = new HashMap<>();
    //存放函数
    private Map<String,OperationInfo> operations = new HashMap<>();

    protected String className = BASE_MBEAN;
    protected String description = null;
    protected String domain = null;
    protected String group = null;
    protected String name = null;

    private NotificationInfo notifications[] = new NotificationInfo[0];
    protected String type = null;

    /** Constructor. Will add default attributes.
     *
     */
    public ManagedBean() {
        AttributeInfo ai=new AttributeInfo();
        ai.setName("modelerType");
        ai.setDescription("Type of the modeled resource. Can be set only once");
        ai.setType("java.lang.String");
        ai.setWriteable(false);
        addAttribute(ai);
    }

    // ------------------------------------------------------------- Properties


    /**
     * 获取MBean的属性
     */
    public AttributeInfo[] getAttributes() {
        AttributeInfo result[] = new AttributeInfo[attributes.size()];
        attributes.values().toArray(result);
        return result;
    }


    public String getClassName() {
        return this.className;
    }

    public void setClassName(String className) {
        mBeanInfoLock.writeLock().lock();
        try {
            this.className = className;
            this.info = null;
        } finally {
            mBeanInfoLock.writeLock().unlock();
        }
    }


    /**
     * The human-readable description of this MBean.
     */
    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        mBeanInfoLock.writeLock().lock();
        try {
            this.description = description;
            this.info = null;
        } finally {
            mBeanInfoLock.writeLock().unlock();
        }
    }


    public String getDomain() {
        return this.domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getGroup() {
        return this.group;
    }

    public void setGroup(String group) {
        this.group = group;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        mBeanInfoLock.writeLock().lock();
        try {
            this.name = name;
            this.info = null;
        } finally {
            mBeanInfoLock.writeLock().unlock();
        }
    }

    public NotificationInfo[] getNotifications() {
        return this.notifications;
    }

    public OperationInfo[] getOperations() {
        OperationInfo[] result = new OperationInfo[operations.size()];
        operations.values().toArray(result);
        return result;
    }

    public String getType() {
        return (this.type);
    }

    public void setType(String type) {
        mBeanInfoLock.writeLock().lock();
        try {
            this.type = type;
            this.info = null;
        } finally {
            mBeanInfoLock.writeLock().unlock();
        }
    }


    // --------------------------------------------------------- Public Methods


    /**
	 * 添加属性
     */
    public void addAttribute(AttributeInfo attribute) {
        attributes.put(attribute.getName(), attribute);
    }


    /**
	 * 添加Notification
     */
    public void addNotification(NotificationInfo notification) {
        mBeanInfoLock.writeLock().lock();
        try {
            NotificationInfo results[] =
                new NotificationInfo[notifications.length + 1];
            System.arraycopy(notifications, 0, results, 0,
                             notifications.length);
            results[notifications.length] = notification;
            notifications = results;
            this.info = null;
        } finally {
            mBeanInfoLock.writeLock().unlock();
        }
    }


    /**
	 * 添加operation函数
     */
    public void addOperation(OperationInfo operation) {
        operations.put(createOperationKey(operation), operation);
    }


    /**
     * 创建MBean对象
     */
    public DynamicMBean createMBean(Object instance)
        throws InstanceNotFoundException,
        MBeanException, RuntimeOperationsException {
    	//BaseModelMBean是一个基础的MBean对象,实现可了javax.management包中的几个接口
        BaseModelMBean mbean = null;

        // 如果当前ManagedBean继承了BASE_MBEAN 则实例化一个BaseModelMBean tomcat的默认实现方式就是这种方式
        if(getClassName().equals(BASE_MBEAN)) {
            // Skip introspection
            mbean = new BaseModelMBean();
        } else {
            Class<?> clazz = null;
            Exception ex = null;
            try {
                clazz = Class.forName(getClassName());
            } catch (Exception e) {
            }

            if( clazz==null ) {
                try {
                    ClassLoader cl= Thread.currentThread().getContextClassLoader();
                    if ( cl != null)
                        clazz= cl.loadClass(getClassName());
                } catch (Exception e) {
                    ex=e;
                }
            }

            if( clazz==null) {
                throw new MBeanException
                    (ex, "Cannot load ModelMBean class " + getClassName());
            }
            try {
                // Stupid - this will set the default minfo first....
                mbean = (BaseModelMBean) clazz.getConstructor().newInstance();
            } catch (RuntimeOperationsException e) {
                throw e;
            } catch (Exception e) {
                throw new MBeanException
                    (e, "Cannot instantiate ModelMBean of class " +
                     getClassName());
            }
        }
        
        //设置当前对象为实例化mbean的managedBean句柄
        mbean.setManagedBean(this);

        // Set the managed resource (if any)
        try {
            if (instance != null)
                mbean.setManagedResource(instance, "ObjectReference");
        } catch (InstanceNotFoundException e) {
            throw e;
        }

        return mbean;
    }


    /**
     * 创建MBeanInfo对象,
     * 通过getMBeanInfo方法会将属性、操作和通知注册到对应实例MBeanAttributeInfo、
     * MBeanOperationInfo以及NotificationInfo然后统一注入到MBeanInfo,
     * 最终其会注入到Mbean的管理器从而实现在jconsole等上进行使用
     */
    MBeanInfo getMBeanInfo() {

        // Return our cached information (if any)
        mBeanInfoLock.readLock().lock();
        try {
            if (info != null) {
                return info;
            }
        } finally {
            mBeanInfoLock.readLock().unlock();
        }

        mBeanInfoLock.writeLock().lock();
        try {
            if (info == null) {
                // Create subordinate information descriptors as required
                AttributeInfo attrs[] = getAttributes();
                MBeanAttributeInfo attributes[] =
                    new MBeanAttributeInfo[attrs.length];
                //遍历属性创建MBeanAttributeInfo
                for (int i = 0; i < attrs.length; i++)
                    attributes[i] = attrs[i].createAttributeInfo();

                OperationInfo opers[] = getOperations();
                MBeanOperationInfo operations[] =
                    new MBeanOperationInfo[opers.length];
                //遍历函数,创建MBeanOperationInfo
                for (int i = 0; i < opers.length; i++)
                    operations[i] = opers[i].createOperationInfo();


                NotificationInfo notifs[] = getNotifications();
                MBeanNotificationInfo notifications[] =
                    new MBeanNotificationInfo[notifs.length];
                //遍历NotificationInfo,创建MBeanNotificationInfo
                for (int i = 0; i < notifs.length; i++)
                    notifications[i] = notifs[i].createNotificationInfo();


                // 创建MBeanInfo对象
                info = new MBeanInfo(getClassName(),
                                     getDescription(),
                                     attributes,
                                     new MBeanConstructorInfo[] {},
                                     operations,
                                     notifications);
            }

            return info;
        } finally {
            mBeanInfoLock.writeLock().unlock();
        }
    }


    
    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder("ManagedBean[");
        sb.append("name=");
        sb.append(name);
        sb.append(", className=");
        sb.append(className);
        sb.append(", description=");
        sb.append(description);
        if (group != null) {
            sb.append(", group=");
            sb.append(group);
        }
        sb.append(", type=");
        sb.append(type);
        sb.append("]");
        return sb.toString();

    }

    /**
     * 获取属性aname的get方法Method对象
     * @param aname
     * @param mbean
     * @param resource
     * @return
     * @throws AttributeNotFoundException
     * @throws ReflectionException
     */
    Method getGetter(String aname, BaseModelMBean mbean, Object resource)
            throws AttributeNotFoundException, ReflectionException {

        Method m = null;
        //根据名称获取AttributeInfo对象
        AttributeInfo attrInfo = attributes.get(aname);
        // Look up the actual operation to be used
        if (attrInfo == null)
            throw new AttributeNotFoundException(" Cannot find attribute " + aname + " for " + resource);
        //获取属性的get方法
        String getMethod = attrInfo.getGetMethod();
        if (getMethod == null)
            throw new AttributeNotFoundException("Cannot find attribute " + aname + " get method name");

        Object object = null;
        NoSuchMethodException exception = null;
        try {
            object = mbean;
            m = object.getClass().getMethod(getMethod, NO_ARGS_PARAM_SIG);
        } catch (NoSuchMethodException e) {
            exception = e;
        }
        if (m== null && resource != null) {
            try {
                object = resource;
                m = object.getClass().getMethod(getMethod, NO_ARGS_PARAM_SIG);
                exception=null;
            } catch (NoSuchMethodException e) {
                exception = e;
            }
        }
        if (exception != null)
            throw new ReflectionException(exception,
                                          "Cannot find getter method " + getMethod);

        return m;
    }

    /**
     * 获取属性aname的set方法Method对象
     * @param aname
     * @param mbean
     * @param resource
     * @return
     * @throws AttributeNotFoundException
     * @throws ReflectionException
     */
    public Method getSetter(String aname, BaseModelMBean bean, Object resource)
            throws AttributeNotFoundException, ReflectionException {

        Method m = null;
        //根据名称获取AttributeInfo对象
        AttributeInfo attrInfo = attributes.get(aname);
        if (attrInfo == null)
            throw new AttributeNotFoundException(" Cannot find attribute " + aname);

        // Look up the actual operation to be used
        String setMethod = attrInfo.getSetMethod();
        if (setMethod == null)
            throw new AttributeNotFoundException("Cannot find attribute " + aname + " set method name");

        String argType=attrInfo.getType();

        Class<?> signature[] =
            new Class[] { BaseModelMBean.getAttributeClass( argType ) };

        Object object = null;
        NoSuchMethodException exception = null;
        try {
            object = bean;
            m = object.getClass().getMethod(setMethod, signature);
        } catch (NoSuchMethodException e) {
            exception = e;
        }
        if (m == null && resource != null) {
            try {
                object = resource;
                m = object.getClass().getMethod(setMethod, signature);
                exception=null;
            } catch (NoSuchMethodException e) {
                exception = e;
            }
        }
        if (exception != null)
            throw new ReflectionException(exception,
                                          "Cannot find setter method " + setMethod +
                    " " + resource);

        return m;
    }

    /**
     * 获取属性aname的一般方法Method对象(除去属性的get,set方法)
     * @param aname
     * @param mbean
     * @param resource
     * @return
     * @throws AttributeNotFoundException
     * @throws ReflectionException
     */
    public Method getInvoke(String aname, Object[] params, String[] signature, BaseModelMBean bean, Object resource)
            throws MBeanException, ReflectionException {

        Method method = null;

        if (params == null)
            params = new Object[0];
        if (signature == null)
            signature = new String[0];
        if (params.length != signature.length)
            throw new RuntimeOperationsException(
                    new IllegalArgumentException(
                            "Inconsistent arguments and signature"),
                    "Inconsistent arguments and signature");

        // Acquire the ModelMBeanOperationInfo information for
        // the requested operation
        OperationInfo opInfo =
                operations.get(createOperationKey(aname, signature));
        if (opInfo == null)
            throw new MBeanException(new ServiceNotFoundException(
                    "Cannot find operation " + aname),
                    "Cannot find operation " + aname);

        // Prepare the signature required by Java reflection APIs
        // FIXME - should we use the signature from opInfo?
        Class<?> types[] = new Class[signature.length];
        for (int i = 0; i < signature.length; i++) {
            types[i] = BaseModelMBean.getAttributeClass(signature[i]);
        }

        // Locate the method to be invoked, either in this MBean itself
        // or in the corresponding managed resource
        // FIXME - Accessible methods in superinterfaces?
        Object object = null;
        Exception exception = null;
        try {
            object = bean;
            method = object.getClass().getMethod(aname, types);
        } catch (NoSuchMethodException e) {
            exception = e;
        }
        try {
            if ((method == null) && (resource != null)) {
                object = resource;
                method = object.getClass().getMethod(aname, types);
            }
        } catch (NoSuchMethodException e) {
            exception = e;
        }
        if (method == null) {
            throw new ReflectionException(exception, "Cannot find method "
                    + aname + " with this signature");
        }

        return method;
    }

    /**
     * 创建函数的标签
     * @param operation
     * @return
     */
    private String createOperationKey(OperationInfo operation) {
        StringBuilder key = new StringBuilder(operation.getName());
        key.append('(');
        for (ParameterInfo parameterInfo: operation.getSignature()) {
            key.append(parameterInfo.getType());
            // Note: A trailing ',' does not matter in this case
            key.append(',');
        }
        key.append(')');

        return key.toString();
    }


    private String createOperationKey(String methodName,
            String[] parameterTypes) {
        StringBuilder key = new StringBuilder(methodName);
        key.append('(');
        for (String parameter: parameterTypes) {
            key.append(parameter);
            // Note: A trailing ',' does not matter in this case
            key.append(',');
        }
        key.append(')');

        return key.toString();
    }
}
