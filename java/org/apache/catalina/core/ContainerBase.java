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

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.File;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.management.ObjectName;

import org.apache.catalina.AccessLog;
import org.apache.catalina.Cluster;
import org.apache.catalina.Container;
import org.apache.catalina.ContainerEvent;
import org.apache.catalina.ContainerListener;
import org.apache.catalina.Context;
import org.apache.catalina.Engine;
import org.apache.catalina.Globals;
import org.apache.catalina.Host;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Loader;
import org.apache.catalina.Pipeline;
import org.apache.catalina.Realm;
import org.apache.catalina.Valve;
import org.apache.catalina.Wrapper;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.util.ContextName;
import org.apache.catalina.util.LifecycleMBeanBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.res.StringManager;



public abstract class ContainerBase extends LifecycleMBeanBase
implements Container {

	private static final org.apache.juli.logging.Log log=
			org.apache.juli.logging.LogFactory.getLog( ContainerBase.class );

	/**
	 * Perform addChild with the permissions of this class.
	 * addChild can be called with the XML parser on the stack,
	 * this allows the XML parser to have fewer privileges than
	 * Tomcat.
	 */
	protected class PrivilegedAddChild implements PrivilegedAction<Void> {

		private final Container child;

		PrivilegedAddChild(Container child) {
			this.child = child;
		}

		@Override
		public Void run() {
			addChildInternal(child);
			return null;
		}

	}


	//子容器
	protected final HashMap<String, Container> children = new HashMap<>();

	protected int backgroundProcessorDelay = -1;

	//事件监听器
	protected final List<ContainerListener> listeners = new CopyOnWriteArrayList<>();

	protected Log logger = null;

	protected String logName = null;


	//host集群
	protected Cluster cluster = null;
	//集群锁
	private final ReadWriteLock clusterLock = new ReentrantReadWriteLock();

	protected String name = null;

	//父容器
	protected Container parent = null;

	//父类加载器
	protected ClassLoader parentClassLoader = null;

	//管道:一种设计模式,将不同级别的容器串联起来
	protected final Pipeline pipeline = new StandardPipeline(this);

	//就是一个存储了用户,密码以及权限的数据对象(host域)
	private volatile Realm realm = null;

	//锁
	private final ReadWriteLock realmLock = new ReentrantReadWriteLock();

	//国际化的StringManager,处理错误日志等
	protected static final StringManager sm =
			StringManager.getManager(Constants.Package);


	//是否启动子容器
	protected boolean startChildren = true;

	/*
	 * JDK中的属性监听器,其实和java事件机制很类似,就是一个辅助类,当属性发生变化的时候,
     * 通知注册的监听器做进一步的反应,注册的一系列监听器在一个Map中存储着
     */
	protected final PropertyChangeSupport support =
			new PropertyChangeSupport(this);


	private Thread thread = null;

	private volatile boolean threadDone = false;

	//客户端请求访问日志
	protected volatile AccessLog accessLog = null;
	private volatile boolean accessLogScanComplete = false;

	//处理启动和停止事件的线程数
	private int startStopThreads = 1;
	//线程池
	protected ThreadPoolExecutor startStopExecutor;

	@Override
	public int getStartStopThreads() {
		return startStopThreads;
	}


	private int getStartStopThreadsInternal() {
		int result = getStartStopThreads();

		//如果大于0直接返回原值
		if (result > 0) {
			return result;
		}
		//获取jvm中处理器的数目+result(0)
		result = Runtime.getRuntime().availableProcessors() + result;
		if (result < 1) {
			result = 1;
		}
		return result;
	}

	@Override
	public void setStartStopThreads(int startStopThreads) {
		this.startStopThreads = startStopThreads;

		ThreadPoolExecutor executor = startStopExecutor;
		if (executor != null) {
			int newThreads = getStartStopThreadsInternal();
			//设置线程池的最大线程数
			executor.setMaximumPoolSize(newThreads);
			//设置线程池的核心线程数
			executor.setCorePoolSize(newThreads);
		}
	}

	//获取当前容器与子容器之间的延迟
	@Override
	public int getBackgroundProcessorDelay() {
		return backgroundProcessorDelay;
	}

	@Override
	public void setBackgroundProcessorDelay(int delay) {
		backgroundProcessorDelay = delay;
	}

	//获取日志对象
	@Override
	public Log getLogger() {
		if (logger != null)
			return (logger);
		logger = LogFactory.getLog(getLogName());
		return (logger);

	}

	//获取日志名称
	@Override
	public String getLogName() {

		if (logName != null) {
			return logName;
		}
		String loggerName = null;
		Container current = this;
		while (current != null) {
			String name = current.getName();
			if ((name == null) || (name.equals(""))) {
				name = "/";
			} else if (name.startsWith("##")) {
				name = "/" + name;
			}
			loggerName = "[" + name + "]"
					+ ((loggerName != null) ? ("." + loggerName) : "");
			current = current.getParent();
		}
		logName = ContainerBase.class.getName() + "." + loggerName;
		return logName;

	}

	//获取集群
	@Override
	public Cluster getCluster() {
		Lock readLock = clusterLock.readLock();
		readLock.lock();
		try {
			if (cluster != null)
				return cluster;

			if (parent != null)
				return parent.getCluster();

			return null;
		} finally {
			readLock.unlock();
		}
	}


	protected Cluster getClusterInternal() {
		Lock readLock = clusterLock.readLock();
		readLock.lock();
		try {
			return cluster;
		} finally {
			readLock.unlock();
		}
	}


	@Override
	public void setCluster(Cluster cluster) {

		Cluster oldCluster = null;
		Lock writeLock = clusterLock.writeLock();
		writeLock.lock();
		try {
			// Change components if necessary
			oldCluster = this.cluster;
			if (oldCluster == cluster)
				return;
			this.cluster = cluster;

			// Stop the old component if necessary
			if (getState().isAvailable() && (oldCluster != null) &&
					(oldCluster instanceof Lifecycle)) {
				try {
					((Lifecycle) oldCluster).stop();
				} catch (LifecycleException e) {
					log.error("ContainerBase.setCluster: stop: ", e);
				}
			}

			// Start the new component if necessary
			if (cluster != null)
				cluster.setContainer(this);

			if (getState().isAvailable() && (cluster != null) &&
					(cluster instanceof Lifecycle)) {
				try {
					((Lifecycle) cluster).start();
				} catch (LifecycleException e) {
					log.error("ContainerBase.setCluster: start: ", e);
				}
			}
		} finally {
			writeLock.unlock();
		}

		// Report this property change to interested listeners
		support.firePropertyChange("cluster", oldCluster, cluster);
	}


	@Override
	public String getName() {
		return (name);
	}

	@Override
	public void setName(String name) {
		String oldName = this.name;
		this.name = name;
		support.firePropertyChange("name", oldName, this.name);
	}


	public boolean getStartChildren() {
		return (startChildren);
	}

	public void setStartChildren(boolean startChildren) {
		boolean oldStartChildren = this.startChildren;
		this.startChildren = startChildren;
		support.firePropertyChange("startChildren", oldStartChildren, this.startChildren);
	}

	@Override
	public Container getParent() {
		return (parent);
	}


	@Override
	public void setParent(Container container) {
		Container oldParent = this.parent;
		this.parent = container;
		support.firePropertyChange("parent", oldParent, this.parent);
	}

	@Override
	public ClassLoader getParentClassLoader() {
		if (parentClassLoader != null)
			return (parentClassLoader);
		if (parent != null) {
			return (parent.getParentClassLoader());
		}
		return (ClassLoader.getSystemClassLoader());

	}

	@Override
	public void setParentClassLoader(ClassLoader parent) {
		ClassLoader oldParentClassLoader = this.parentClassLoader;
		this.parentClassLoader = parent;
		support.firePropertyChange("parentClassLoader", oldParentClassLoader,
				this.parentClassLoader);
	}

	@Override
	public Pipeline getPipeline() {
		return (this.pipeline);
	}

	//获取host域Realm,连同父容器的一块获取
	@Override
	public Realm getRealm() {
		Lock l = realmLock.readLock();
		l.lock();
		try {
			if (realm != null)
				return (realm);
			if (parent != null)
				return (parent.getRealm());
			return null;
		} finally {
			l.unlock();
		}
	}

	//获取当前容器的Realm
	protected Realm getRealmInternal() {
		Lock l = realmLock.readLock();
		l.lock();
		try {
			return realm;
		} finally {
			l.unlock();
		}
	}


	@Override
	public void setRealm(Realm realm) {
		Lock l = realmLock.writeLock();
		l.lock();
		try {
			// Change components if necessary
			Realm oldRealm = this.realm;
			if (oldRealm == realm)
				return;
			this.realm = realm;
			// Stop the old component if necessary
			if (getState().isAvailable() && (oldRealm != null) &&
					(oldRealm instanceof Lifecycle)) {
				try {
					((Lifecycle) oldRealm).stop();
				} catch (LifecycleException e) {
					log.error("ContainerBase.setRealm: stop: ", e);
				}
			}
			// Start the new component if necessary
			if (realm != null)
				realm.setContainer(this);
			if (getState().isAvailable() && (realm != null) &&
					(realm instanceof Lifecycle)) {
				try {
					((Lifecycle) realm).start();
				} catch (LifecycleException e) {
					log.error("ContainerBase.setRealm: start: ", e);
				}
			}
			// Report this property change to interested listeners
			support.firePropertyChange("realm", oldRealm, this.realm);
		} finally {
			l.unlock();
		}

	}


	@Override
	public void addChild(Container child) {
		if (Globals.IS_SECURITY_ENABLED) {
			PrivilegedAction<Void> dp =
					new PrivilegedAddChild(child);
			AccessController.doPrivileged(dp);
		} else {
			addChildInternal(child);
		}
	}

	private void addChildInternal(Container child) {
		if( log.isDebugEnabled() )
			log.debug("Add child " + child + " " + this);
		synchronized(children) {
			if (children.get(child.getName()) != null)
				throw new IllegalArgumentException("addChild:  Child name '" +
						child.getName() +
						"' is not unique");
			child.setParent(this);  // May throw IAE
			children.put(child.getName(), child);
		}

		// Start child
		// Don't do this inside sync block - start can be a slow process and
		// locking the children object can cause problems elsewhere
		try {
			if ((getState().isAvailable() ||
					LifecycleState.STARTING_PREP.equals(getState())) &&
					startChildren) {
				child.start();
			}
		} catch (LifecycleException e) {
			log.error("ContainerBase.addChild: start: ", e);
			throw new IllegalStateException("ContainerBase.addChild: start: " + e);
		} finally {
			fireContainerEvent(ADD_CHILD_EVENT, child);
		}
	}


	@Override
	public void addContainerListener(ContainerListener listener) {
		listeners.add(listener);
	}

	@Override
	public void addPropertyChangeListener(PropertyChangeListener listener) {
		support.addPropertyChangeListener(listener);
	}


	@Override
	public Container findChild(String name) {
		if (name == null)
			return (null);
		synchronized (children) {
			return children.get(name);
		}
	}


	@Override
	public Container[] findChildren() {

		synchronized (children) {
			Container results[] = new Container[children.size()];
			return children.values().toArray(results);
		}

	}


	@Override
	public ContainerListener[] findContainerListeners() {
		ContainerListener[] results =
				new ContainerListener[0];
		return listeners.toArray(results);
	}


	@Override
	public void removeChild(Container child) {
		if (child == null) {
			return;
		}
		try {
			if (child.getState().isAvailable()) {
				child.stop();
			}
		} catch (LifecycleException e) {
			log.error("ContainerBase.removeChild: stop: ", e);
		}

		try {
			if (!LifecycleState.DESTROYING.equals(child.getState())) {
				child.destroy();
			}
		} catch (LifecycleException e) {
			log.error("ContainerBase.removeChild: destroy: ", e);
		}

		synchronized(children) {
			if (children.get(child.getName()) == null)
				return;
			children.remove(child.getName());
		}

		fireContainerEvent(REMOVE_CHILD_EVENT, child);
	}


	@Override
	public void removeContainerListener(ContainerListener listener) {
		listeners.remove(listener);
	}


	@Override
	public void removePropertyChangeListener(PropertyChangeListener listener) {
		support.removePropertyChangeListener(listener);
	}


	@Override
	protected void initInternal() throws LifecycleException {
		BlockingQueue<Runnable> startStopQueue = new LinkedBlockingQueue<>();
		startStopExecutor = new ThreadPoolExecutor(
				getStartStopThreadsInternal(),
				getStartStopThreadsInternal(), 10, TimeUnit.SECONDS,
				startStopQueue,
				new StartStopThreadFactory(getName() + "-startStop-"));
		startStopExecutor.allowCoreThreadTimeOut(true);
		super.initInternal();
	}


	/**
	 * Start this component and implement the requirements
	 */
	@Override
	protected synchronized void startInternal() throws LifecycleException {

		// Start our subordinate components, if any
		logger = null;
		getLogger();
		Cluster cluster = getClusterInternal();
		if ((cluster != null) && (cluster instanceof Lifecycle))
			((Lifecycle) cluster).start();
		Realm realm = getRealmInternal();
		if ((realm != null) && (realm instanceof Lifecycle))
			((Lifecycle) realm).start();

		// Start our child containers, if any
		Container children[] = findChildren();
		List<Future<Void>> results = new ArrayList<>();
		for (int i = 0; i < children.length; i++) {
			results.add(startStopExecutor.submit(new StartChild(children[i])));
		}

		boolean fail = false;
		for (Future<Void> result : results) {
			try {
				result.get();
			} catch (Exception e) {
				log.error(sm.getString("containerBase.threadedStartFailed"), e);
				fail = true;
			}

		}
		if (fail) {
			throw new LifecycleException(
					sm.getString("containerBase.threadedStartFailed"));
		}

		// Start the Valves in our pipeline (including the basic), if any
		if (pipeline instanceof Lifecycle)
			((Lifecycle) pipeline).start();


		setState(LifecycleState.STARTING);

		// Start our thread
		threadStart();

	}


	/**
	 * Stop this component and implement the requirements
	 */
	@Override
	protected synchronized void stopInternal() throws LifecycleException {

		// Stop our thread
		threadStop();

		setState(LifecycleState.STOPPING);

		// Stop the Valves in our pipeline (including the basic), if any
		if (pipeline instanceof Lifecycle &&
				((Lifecycle) pipeline).getState().isAvailable()) {
			((Lifecycle) pipeline).stop();
		}

		// Stop our child containers, if any
		Container children[] = findChildren();
		List<Future<Void>> results = new ArrayList<>();
		for (int i = 0; i < children.length; i++) {
			results.add(startStopExecutor.submit(new StopChild(children[i])));
		}

		boolean fail = false;
		for (Future<Void> result : results) {
			try {
				result.get();
			} catch (Exception e) {
				log.error(sm.getString("containerBase.threadedStopFailed"), e);
				fail = true;
			}
		}
		if (fail) {
			throw new LifecycleException(
					sm.getString("containerBase.threadedStopFailed"));
		}

		// Stop our subordinate components, if any
		Realm realm = getRealmInternal();
		if ((realm != null) && (realm instanceof Lifecycle)) {
			((Lifecycle) realm).stop();
		}
		Cluster cluster = getClusterInternal();
		if ((cluster != null) && (cluster instanceof Lifecycle)) {
			((Lifecycle) cluster).stop();
		}
	}

	@Override
	protected void destroyInternal() throws LifecycleException {

		Realm realm = getRealmInternal();
		if ((realm != null) && (realm instanceof Lifecycle)) {
			((Lifecycle) realm).destroy();
		}
		Cluster cluster = getClusterInternal();
		if ((cluster != null) && (cluster instanceof Lifecycle)) {
			((Lifecycle) cluster).destroy();
		}

		// Stop the Valves in our pipeline (including the basic), if any
		if (pipeline instanceof Lifecycle) {
			((Lifecycle) pipeline).destroy();
		}

		// Remove children now this container is being destroyed
		for (Container child : findChildren()) {
			removeChild(child);
		}

		// Required if the child is destroyed directly.
		if (parent != null) {
			parent.removeChild(this);
		}

		// If init fails, this may be null
		if (startStopExecutor != null) {
			startStopExecutor.shutdownNow();
		}

		super.destroyInternal();
	}


	@Override
	public void logAccess(Request request, Response response, long time,
			boolean useDefault) {

		boolean logged = false;

		if (getAccessLog() != null) {
			getAccessLog().log(request, response, time);
			logged = true;
		}

		if (getParent() != null) {
			// No need to use default logger once request/response has been logged
			// once
			getParent().logAccess(request, response, time, (useDefault && !logged));
		}
	}

	@Override
	public AccessLog getAccessLog() {

		if (accessLogScanComplete) {
			return accessLog;
		}

		AccessLogAdapter adapter = null;
		Valve valves[] = getPipeline().getValves();
		for (Valve valve : valves) {
			if (valve instanceof AccessLog) {
				if (adapter == null) {
					adapter = new AccessLogAdapter((AccessLog) valve);
				} else {
					adapter.add((AccessLog) valve);
				}
			}
		}
		if (adapter != null) {
			accessLog = adapter;
		}
		accessLogScanComplete = true;
		return accessLog;
	}

	// ------------------------------------------------------- Pipeline Methods


	/**
	 * Convenience method, intended for use by the digester to simplify the
	 * process of adding Valves to containers. See
	 */
	public synchronized void addValve(Valve valve) {

		pipeline.addValve(valve);
	}

	@Override
	public void backgroundProcess() {

		if (!getState().isAvailable())
			return;

		Cluster cluster = getClusterInternal();
		if (cluster != null) {
			try {
				cluster.backgroundProcess();
			} catch (Exception e) {
				log.warn(sm.getString("containerBase.backgroundProcess.cluster",
						cluster), e);
			}
		}
		Realm realm = getRealmInternal();
		if (realm != null) {
			try {
				realm.backgroundProcess();
			} catch (Exception e) {
				log.warn(sm.getString("containerBase.backgroundProcess.realm", realm), e);
			}
		}
		Valve current = pipeline.getFirst();
		while (current != null) {
			try {
				current.backgroundProcess();
			} catch (Exception e) {
				log.warn(sm.getString("containerBase.backgroundProcess.valve", current), e);
			}
			current = current.getNext();
		}
		fireLifecycleEvent(Lifecycle.PERIODIC_EVENT, null);
	}


	@Override
	public File getCatalinaBase() {
		if (parent == null) {
			return null;
		}
		return parent.getCatalinaBase();
	}


	@Override
	public File getCatalinaHome() {
		if (parent == null) {
			return null;
		}
		return parent.getCatalinaHome();
	}


	// ------------------------------------------------------ Protected Methods

	/**
	 * Notify all container event listeners that a particular event has
	 * occurred for this Container.  The default implementation performs
	 * this notification synchronously using the calling thread.
	 */
	@Override
	public void fireContainerEvent(String type, Object data) {

		if (listeners.size() < 1)
			return;

		ContainerEvent event = new ContainerEvent(this, type, data);
		// Note for each uses an iterator internally so this is safe
		for (ContainerListener listener : listeners) {
			listener.containerEvent(event);
		}
	}


	// -------------------- JMX and Registration  --------------------

	@Override
	protected String getDomainInternal() {

		Container p = this.getParent();
		if (p == null) {
			return null;
		} else {
			return p.getDomain();
		}
	}


	@Override
	public String getMBeanKeyProperties() {
		Container c = this;
		StringBuilder keyProperties = new StringBuilder();
		int containerCount = 0;

		// Work up container hierarchy, add a component to the name for
		// each container
		while (!(c instanceof Engine)) {
			if (c instanceof Wrapper) {
				keyProperties.insert(0, ",servlet=");
				keyProperties.insert(9, c.getName());
			} else if (c instanceof Context) {
				keyProperties.insert(0, ",context=");
				ContextName cn = new ContextName(c.getName(), false);
				keyProperties.insert(9,cn.getDisplayName());
			} else if (c instanceof Host) {
				keyProperties.insert(0, ",host=");
				keyProperties.insert(6, c.getName());
			} else if (c == null) {
				// May happen in unit testing and/or some embedding scenarios
				keyProperties.append(",container");
				keyProperties.append(containerCount++);
				keyProperties.append("=null");
				break;
			} else {
				// Should never happen...
				keyProperties.append(",container");
				keyProperties.append(containerCount++);
				keyProperties.append('=');
				keyProperties.append(c.getName());
			}
			c = c.getParent();
		}
		return keyProperties.toString();
	}

	public ObjectName[] getChildren() {
		List<ObjectName> names = new ArrayList<>(children.size());
		Iterator<Container>  it = children.values().iterator();
		while (it.hasNext()) {
			Object next = it.next();
			if (next instanceof ContainerBase) {
				names.add(((ContainerBase)next).getObjectName());
			}
		}
		return names.toArray(new ObjectName[names.size()]);
	}


	// -------------------- Background Thread --------------------

	/**
	 * 启动后台线程
	 * Start the background thread that will periodically check for
	 * session timeouts.
	 */
	protected void threadStart() {

		if (thread != null)
			return;
		if (backgroundProcessorDelay <= 0)
			return;

		threadDone = false;
		String threadName = "ContainerBackgroundProcessor[" + toString() + "]";
		thread = new Thread(new ContainerBackgroundProcessor(), threadName);
		//设置为守护线程
		thread.setDaemon(true);
		thread.start();

	}


	/**
	 * Stop the background thread that is periodically checking for
	 * session timeouts.
	 */
	protected void threadStop() {

		if (thread == null)
			return;

		threadDone = true;
		thread.interrupt();
		try {
			thread.join();
		} catch (InterruptedException e) {
			// Ignore
		}

		thread = null;

	}


	// -------------------------------------- ContainerExecuteDelay Inner Class


	/**
	 * Private thread class to invoke the backgroundProcess method
	 * of this container and its children after a fixed delay.
	 */
	protected class ContainerBackgroundProcessor implements Runnable {

		@Override
		public void run() {
			Throwable t = null;
			String unexpectedDeathMessage = sm.getString(
					"containerBase.backgroundProcess.unexpectedThreadDeath",
					Thread.currentThread().getName());
			try {
				//通过while循环周期性的执行任务
				while (!threadDone) {
					try {
						Thread.sleep(backgroundProcessorDelay * 1000L);
					} catch (InterruptedException e) {
						// Ignore
					}
					if (!threadDone) {
						processChildren(ContainerBase.this);
					}
				}
			} catch (RuntimeException|Error e) {
				t = e;
				throw e;
			} finally {
				if (!threadDone) {
					log.error(unexpectedDeathMessage, t);
				}
			}
		}

		protected void processChildren(Container container) {
			ClassLoader originalClassLoader = null;

			try {
				if (container instanceof Context) {
					Loader loader = ((Context) container).getLoader();
					// Loader will be null for FailedContext instances
					if (loader == null) {
						return;
					}

					// Ensure background processing for Contexts and Wrappers
					// is performed under the web app's class loader
					originalClassLoader = ((Context) container).bind(false, null);
				}
				container.backgroundProcess();
				Container[] children = container.findChildren();
				for (int i = 0; i < children.length; i++) {
					if (children[i].getBackgroundProcessorDelay() <= 0) {
						processChildren(children[i]);
					}
				}
			} catch (Throwable t) {
				ExceptionUtils.handleThrowable(t);
				log.error("Exception invoking periodic operation: ", t);
			} finally {
				if (container instanceof Context) {
					((Context) container).unbind(false, originalClassLoader);
				}
			}
		}
	}


	// ----------------------------- Inner classes used with start/stop Executor

	private static class StartChild implements Callable<Void> {

		private Container child;

		public StartChild(Container child) {
			this.child = child;
		}

		@Override
		public Void call() throws LifecycleException {
			child.start();
			return null;
		}
	}

	private static class StopChild implements Callable<Void> {

		private Container child;

		public StopChild(Container child) {
			this.child = child;
		}

		@Override
		public Void call() throws LifecycleException {
			if (child.getState().isAvailable()) {
				child.stop();
			}
			return null;
		}
	}

	private static class StartStopThreadFactory implements ThreadFactory {
		private final ThreadGroup group;
		private final AtomicInteger threadNumber = new AtomicInteger(1);
		private final String namePrefix;

		public StartStopThreadFactory(String namePrefix) {
			SecurityManager s = System.getSecurityManager();
			group = (s != null) ? s.getThreadGroup() : Thread.currentThread().getThreadGroup();
			this.namePrefix = namePrefix;
		}

		@Override
		public Thread newThread(Runnable r) {
			Thread thread = new Thread(group, r, namePrefix + threadNumber.getAndIncrement());
			thread.setDaemon(true);
			return thread;
		}
	}
}
