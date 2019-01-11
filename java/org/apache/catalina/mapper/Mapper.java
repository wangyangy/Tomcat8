/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.catalina.mapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.catalina.Context;
import org.apache.catalina.Host;
import org.apache.catalina.WebResource;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.Wrapper;
import org.apache.tomcat.util.buf.Ascii;
import org.apache.tomcat.util.buf.CharChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.res.StringManager;

/**
 * Mapper, which implements the servlet API mapping rules (which are derived
 * from the HTTP rules).
 *
 * @author Remy Maucherat
 * 该类的核心功能是实现请求的路由映射,根据请求路径得到相应的servlet,在该类中大量使用了内部类的形式
 */
public final class Mapper {


    private static final org.apache.juli.logging.Log log =
        org.apache.juli.logging.LogFactory.getLog(Mapper.class);

    static final StringManager sm =
        StringManager.getManager(Mapper.class.getPackage().getName());

    // ----------------------------------------------------- Instance Variables


    /**
     * Array containing the virtual hosts definitions.
     * 是该类的一个内部类,虚拟的host
     */
    volatile MappedHost[] hosts = new MappedHost[0];


    /**
     * Default host name.默认名称
     */
    String defaultHostName = null;


    /**
     * Mapping from Context object to Context version to support
     * RequestDispatcher mappings.
     * 支持转发操作的RequestDispatcher
     */
    Map<Context, ContextVersion> contextObjectToContextVersionMap =
            new ConcurrentHashMap<>();


    // --------------------------------------------------------- Public Methods

    /**
     * Set default host.
     *
     * @param defaultHostName Default host name
     */
    public void setDefaultHostName(String defaultHostName) {
        this.defaultHostName = defaultHostName;
    }

    /**
     * 添加一个新host到mapper中
     * Add a new host to the mapper.
     *
     * @param name Virtual host name
     * @param aliases Alias names for the virtual host
     * @param host Host object
     */
    public synchronized void addHost(String name, String[] aliases,
                                     Host host) {
    	//申请一个MappedHost新数组
        MappedHost[] newHosts = new MappedHost[hosts.length + 1];
        //构造MappedHost对象
        MappedHost newHost = new MappedHost(name, host);
        //插入到相应的位置
        if (insertMap(hosts, newHosts, newHost)) {
        	//变量重新赋值
            hosts = newHosts;
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("mapper.addHost.success", name));
            }
        } else {
        	//有重复的元素
            MappedHost duplicate = hosts[find(hosts, name)];
            //元素的object和host是相同的,说明host已经存在
            if (duplicate.object == host) {
                // The host is already registered in the mapper.
                // E.g. it might have been added by addContextVersion()
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("mapper.addHost.sameHost", name));
                }
                newHost = duplicate;
            //映射错误,说明一个host有了多个映射地址
            } else {
                log.error(sm.getString("mapper.duplicateHost", name,
                        duplicate.getRealHostName()));
                // Do not add aliases, as removeHost(hostName) won't be able to
                // remove them
                return;
            }
        }
        //处理别名
        List<MappedHost> newAliases = new ArrayList<>(aliases.length);
        for (String alias : aliases) {
            MappedHost newAlias = new MappedHost(alias, newHost);
            if (addHostAliasImpl(newAlias)) {
            	//添加别名
                newAliases.add(newAlias);
            }
        }
        //设置别名
        newHost.addAliases(newAliases);
    }


    /**删除host,从MappedHost中
     * Remove a host from the mapper.
     *
     * @param name Virtual host name
     */
    public synchronized void removeHost(String name) {
        // 找到要删除的元素
        MappedHost host = exactFind(hosts, name);
        if (host == null || host.isAlias()) {
            return;
        }
        //做个副本,先不要修改原数组,注意clone是浅拷贝
        MappedHost[] newHosts = hosts.clone();
        // 将不删除的元素拷贝过来,这里只是拷贝引用并不涉及元素的真实拷贝
        int j = 0;
        for (int i = 0; i < newHosts.length; i++) {
            if (newHosts[i].getRealHost() != host) {
                newHosts[j++] = newHosts[i];
            }
        }
        //重新给数组元素复值(将引用的地址改变了,最后的元素没了,j)
        hosts = Arrays.copyOf(newHosts, j);
    }

    /**对一个host添加别名
     * Add an alias to an existing host.
     * @param name  The name of the host
     * @param alias The alias to add
     */
    public synchronized void addHostAlias(String name, String alias) {
        MappedHost realHost = exactFind(hosts, name);
        if (realHost == null) {
            // Should not be adding an alias for a host that doesn't exist but
            // just in case...
            return;
        }
        MappedHost newAlias = new MappedHost(alias, realHost);
        if (addHostAliasImpl(newAlias)) {
            realHost.addAlias(newAlias);
        }
    }

    //处理别名的情况
    private synchronized boolean addHostAliasImpl(MappedHost newAlias) {
    	//申请一个数组
        MappedHost[] newHosts = new MappedHost[hosts.length + 1];
        //插入到相应的位置
        if (insertMap(hosts, newHosts, newAlias)) {
        	//重新赋值变量
            hosts = newHosts;
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("mapper.addHostAlias.success",
                        newAlias.name, newAlias.getRealHostName()));
            }
            return true;
        //插入失败
        } else {
        	//有重复的别名
            MappedHost duplicate = hosts[find(hosts, newAlias.name)];
            //别名已经有了,不用添加
            if (duplicate.getRealHost() == newAlias.getRealHost()) {
                // A duplicate Alias for the same Host.
                // A harmless redundancy. E.g.
                // <Host name="localhost"><Alias>localhost</Alias></Host>
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("mapper.addHostAlias.sameHost",
                            newAlias.name, newAlias.getRealHostName()));
                }
                return false;
            }
            log.error(sm.getString("mapper.duplicateHostAlias", newAlias.name,
                    newAlias.getRealHostName(), duplicate.getRealHostName()));
            return false;
        }
    }

    /**
     * 删除host的别名
     * Remove a host alias
     * @param alias The alias to remove
     */
    public synchronized void removeHostAlias(String alias) {
        // Find and remove the alias
    	// 根据别名找到MappedHost
        MappedHost hostMapping = exactFind(hosts, alias);
        if (hostMapping == null || !hostMapping.isAlias()) {
            return;
        }
        MappedHost[] newHosts = new MappedHost[hosts.length - 1];
        //根据别名找到MappedHost并删除MappedHost,之后将MappedHost的别名也删除
        if (removeMap(hosts, newHosts, alias)) {
            hosts = newHosts;
            hostMapping.getRealHost().removeAlias(hostMapping);
        }

    }

    /**更新ContextList
     * Replace {@link MappedHost#contextList} field in <code>realHost</code> and
     * all its aliases with a new value.
     */
    private void updateContextList(MappedHost realHost,
            ContextList newContextList) {
    	//readHost和别名中的contextList都要更新
        realHost.contextList = newContextList;
        for (MappedHost alias : realHost.getAliases()) {
            alias.contextList = newContextList;
        }
    }

    /**
     * Add a new Context to an existing Host.
     *
     * @param hostName Virtual host name this context belongs to
     * @param host Host object
     * @param path Context path
     * @param version Context version
     * @param context Context object
     * @param welcomeResources Welcome files defined for this context
     * @param resources Static resources of the context
     * @deprecated Use {@link #addContextVersion(String, Host, String, String, Context, String[], WebResourceRoot, Collection)}
     */
    @Deprecated
    public void addContextVersion(String hostName, Host host, String path,
            String version, Context context, String[] welcomeResources,
            WebResourceRoot resources) {
        addContextVersion(hostName, host, path, version, context,
                welcomeResources, resources, null);
    }

    /**
     * 添加一个新的Context到Host中
     * Add a new Context to an existing Host.
     *
     * @param hostName Virtual host name this context belongs to
     * @param host Host object
     * @param path Context path
     * @param version Context version
     * @param context Context object
     * @param welcomeResources Welcome files defined for this context
     * @param resources Static resources of the context
     * @param wrappers Information on wrapper mappings
     */
    public void addContextVersion(String hostName, Host host, String path,
            String version, Context context, String[] welcomeResources,
            WebResourceRoot resources, Collection<WrapperMappingInfo> wrappers) {
    	//根据hostName找到MappedHost
        MappedHost mappedHost  = exactFind(hosts, hostName);
        //没有Host
        if (mappedHost == null) {
        	//则新建一个Host并添加到Mapper中
            addHost(hostName, new String[0], host);
            mappedHost = exactFind(hosts, hostName);
            if (mappedHost == null) {
                log.error("No host found: " + hostName);
                return;
            }
        }
        //如果是host的别名
        if (mappedHost.isAlias()) {
            log.error("No host found: " + hostName);
            return;
        }
        //获取'/'的数目
        int slashCount = slashCount(path);
        synchronized (mappedHost) {
        	//新建ContextVersion
            ContextVersion newContextVersion = new ContextVersion(version,
                    path, slashCount, context, resources, welcomeResources);
            //将Wrapper添加到Context中
            if (wrappers != null) {
                addWrappers(newContextVersion, wrappers);
            }
            //获取host的Context
            ContextList contextList = mappedHost.contextList;
            MappedContext mappedContext = exactFind(contextList.contexts, path);
            //没有找到要添加的Context
            if (mappedContext == null) {
            	//新建一个Context
                mappedContext = new MappedContext(path, newContextVersion);
                //添加到集合中
                ContextList newContextList = contextList.addContext(
                        mappedContext, slashCount);
                if (newContextList != null) {
                	//更新一下
                    updateContextList(mappedHost, newContextList);
                    contextObjectToContextVersionMap.put(context, newContextVersion);
                }
            //找到了
            } else {
                ContextVersion[] contextVersions = mappedContext.versions;
                ContextVersion[] newContextVersions = new ContextVersion[contextVersions.length + 1];
                //直接插入新数组中
                if (insertMap(contextVersions, newContextVersions,
                        newContextVersion)) {
                    mappedContext.versions = newContextVersions;
                    contextObjectToContextVersionMap.put(context, newContextVersion);
                //有重复的元素
                } else {
                    // Re-registration after Context.reload()
                    // Replace ContextVersion with the new one
                	//更新
                    int pos = find(contextVersions, version);
                    if (pos >= 0 && contextVersions[pos].name.equals(version)) {
                        contextVersions[pos] = newContextVersion;
                        contextObjectToContextVersionMap.put(context, newContextVersion);
                    }
                }
            }
        }

    }


    /**
     * 从host中删除Context
     * Remove a context from an existing host.
     *
     * @param ctxt      The actual context
     * @param hostName  Virtual host name this context belongs to
     * @param path      Context path
     * @param version   Context version
     */
    public void removeContextVersion(Context ctxt, String hostName,
            String path, String version) {

        contextObjectToContextVersionMap.remove(ctxt);
        //找到host
        MappedHost host = exactFind(hosts, hostName);
        if (host == null || host.isAlias()) {
            return;
        }

        synchronized (host) {
        	//host中的context列表
            ContextList contextList = host.contextList;
            //根据path找到context
            MappedContext context = exactFind(contextList.contexts, path);
            if (context == null) {
                return;
            }
            //context对赢的wrapper
            ContextVersion[] contextVersions = context.versions;
            ContextVersion[] newContextVersions =
                new ContextVersion[contextVersions.length - 1];
            //删除元素
            if (removeMap(contextVersions, newContextVersions, version)) {
                if (newContextVersions.length == 0) {
                    // Remove the context
                    ContextList newContextList = contextList.removeContext(path);
                    if (newContextList != null) {
                        updateContextList(host, newContextList);
                    }
                } else {
                    context.versions = newContextVersions;
                }
            }
        }
    }


    /**
     * 改变context标记
     * Mark a context as being reloaded. Reversion of this state is performed
     * by calling <code>addContextVersion(...)</code> when context starts up.
     *
     * @param ctxt      The actual context
     * @param hostName  Virtual host name this context belongs to
     * @param contextPath Context path
     * @param version   Context version
     */
    public void pauseContextVersion(Context ctxt, String hostName,
            String contextPath, String version) {

        ContextVersion contextVersion = findContextVersion(hostName,
                contextPath, version, true);
        if (contextVersion == null || !ctxt.equals(contextVersion.object)) {
            return;
        }
        contextVersion.markPaused();
    }


    //查找ContextVersion
    private ContextVersion findContextVersion(String hostName,
            String contextPath, String version, boolean silent) {
    	//先找host
        MappedHost host = exactFind(hosts, hostName);
        if (host == null || host.isAlias()) {
            if (!silent) {
                log.error("No host found: " + hostName);
            }
            return null;
        }
        //再找context
        MappedContext context = exactFind(host.contextList.contexts,
                contextPath);
        if (context == null) {
            if (!silent) {
                log.error("No context found: " + contextPath);
            }
            return null;
        }
        //再找wrapper
        ContextVersion contextVersion = exactFind(context.versions, version);
        if (contextVersion == null) {
            if (!silent) {
                log.error("No context version found: " + contextPath + " "
                        + version);
            }
            return null;
        }
        return contextVersion;
    }

    //添加wrapper
    public void addWrapper(String hostName, String contextPath, String version,
                           String path, Wrapper wrapper, boolean jspWildCard,
                           boolean resourceOnly) {
        ContextVersion contextVersion = findContextVersion(hostName,
                contextPath, version, false);
        if (contextVersion == null) {
            return;
        }
        addWrapper(contextVersion, path, wrapper, jspWildCard, resourceOnly);
    }

    //添加wrapper
    public void addWrappers(String hostName, String contextPath,
            String version, Collection<WrapperMappingInfo> wrappers) {
        ContextVersion contextVersion = findContextVersion(hostName,
                contextPath, version, false);
        if (contextVersion == null) {
            return;
        }
        addWrappers(contextVersion, wrappers);
    }

    /**
     * 将wrappers添加到context中
     * Adds wrappers to the given context.
     *
     * @param contextVersion The context to which to add the wrappers
     * @param wrappers Information on wrapper mappings
     */
    private void addWrappers(ContextVersion contextVersion,
            Collection<WrapperMappingInfo> wrappers) {
        for (WrapperMappingInfo wrapper : wrappers) {
            addWrapper(contextVersion, wrapper.getMapping(),
                    wrapper.getWrapper(), wrapper.isJspWildCard(),
                    wrapper.isResourceOnly());
        }
    }

    /**
     * Adds a wrapper to the given context.
     *
     * @param context The context to which to add the wrapper
     * @param path Wrapper mapping
     * @param wrapper The Wrapper object
     * @param jspWildCard true if the wrapper corresponds to the JspServlet
     *   and the mapping path contains a wildcard; false otherwise
     * @param resourceOnly true if this wrapper always expects a physical
     *                     resource to be present (such as a JSP)
     */
    protected void addWrapper(ContextVersion context, String path,
            Wrapper wrapper, boolean jspWildCard, boolean resourceOnly) {

        synchronized (context) {
        	//如果path以/*结尾,则是Wildcard wrapper(通配符)
            if (path.endsWith("/*")) {
                // Wildcard wrapper前面精确的名称
                String name = path.substring(0, path.length() - 2);
                //新建Wrapper
                MappedWrapper newWrapper = new MappedWrapper(name, wrapper,
                        jspWildCard, resourceOnly);
                //获取context的通配符Wrappers
                MappedWrapper[] oldWrappers = context.wildcardWrappers;
                MappedWrapper[] newWrappers = new MappedWrapper[oldWrappers.length + 1];
                //将新建的Wrapper插入进去
                if (insertMap(oldWrappers, newWrappers, newWrapper)) {
                    context.wildcardWrappers = newWrappers;
                    int slashCount = slashCount(newWrapper.name);
                    if (slashCount > context.nesting) {
                        context.nesting = slashCount;
                    }
                }
            //如果path以*.结尾,则是Extension wrapper(扩展)
            } else if (path.startsWith("*.")) {
                // Extension wrapper
                String name = path.substring(2);
                //新建Wrapper
                MappedWrapper newWrapper = new MappedWrapper(name, wrapper,
                        jspWildCard, resourceOnly);
                //获取context的扩展Wrappers
                MappedWrapper[] oldWrappers = context.extensionWrappers;
                MappedWrapper[] newWrappers =
                    new MappedWrapper[oldWrappers.length + 1];
                //将新建的Wrapper插入进去
                if (insertMap(oldWrappers, newWrappers, newWrapper)) {
                    context.extensionWrappers = newWrappers;
                }
            //如果以/结尾则是默认wrapper(默认)
            } else if (path.equals("/")) {
                //新建默认Wrapper. Default wrapper
                MappedWrapper newWrapper = new MappedWrapper("", wrapper,
                        jspWildCard, resourceOnly);
                //设置默认Wrapper
                context.defaultWrapper = newWrapper;
            //否则是精确wrapper
            } else {
                // Exact wrapper
                final String name;
                if (path.length() == 0) {
                    // Special case for the Context Root mapping which is
                    // treated as an exact match
                    name = "/";
                } else {
                    name = path;
                }
                //新建Wrapper
                MappedWrapper newWrapper = new MappedWrapper(name, wrapper,
                        jspWildCard, resourceOnly);
                //获取context的精确Wrappers
                MappedWrapper[] oldWrappers = context.exactWrappers;
                MappedWrapper[] newWrappers = new MappedWrapper[oldWrappers.length + 1];
                //将新建的Wrapper插入进去
                if (insertMap(oldWrappers, newWrappers, newWrapper)) {
                    context.exactWrappers = newWrappers;
                }
            }
        }
    }


    /**
     * 从context中删除wrapper
     * Remove a wrapper from an existing context.
     *
     * @param hostName Virtual host name this wrapper belongs to
     * @param contextPath Context path this wrapper belongs to
     * @param path Wrapper mapping
     */
    public void removeWrapper(String hostName, String contextPath,
            String version, String path) {
        ContextVersion contextVersion = findContextVersion(hostName,
                contextPath, version, true);
        if (contextVersion == null || contextVersion.isPaused()) {
            return;
        }
        removeWrapper(contextVersion, path);
    }

    //具体的删除Wrapper的函数
    protected void removeWrapper(ContextVersion context, String path) {

        if (log.isDebugEnabled()) {
            log.debug(sm.getString("mapper.removeWrapper", context.name, path));
        }

        synchronized (context) {
            if (path.endsWith("/*")) {
                // Wildcard wrapper
                String name = path.substring(0, path.length() - 2);
                MappedWrapper[] oldWrappers = context.wildcardWrappers;
                if (oldWrappers.length == 0) {
                    return;
                }
                MappedWrapper[] newWrappers =
                    new MappedWrapper[oldWrappers.length - 1];
                if (removeMap(oldWrappers, newWrappers, name)) {
                    // Recalculate nesting
                    context.nesting = 0;
                    for (int i = 0; i < newWrappers.length; i++) {
                        int slashCount = slashCount(newWrappers[i].name);
                        if (slashCount > context.nesting) {
                            context.nesting = slashCount;
                        }
                    }
                    context.wildcardWrappers = newWrappers;
                }
            } else if (path.startsWith("*.")) {
                // Extension wrapper
                String name = path.substring(2);
                MappedWrapper[] oldWrappers = context.extensionWrappers;
                if (oldWrappers.length == 0) {
                    return;
                }
                MappedWrapper[] newWrappers =
                    new MappedWrapper[oldWrappers.length - 1];
                if (removeMap(oldWrappers, newWrappers, name)) {
                    context.extensionWrappers = newWrappers;
                }
            } else if (path.equals("/")) {
                // Default wrapper
                context.defaultWrapper = null;
            } else {
                // Exact wrapper
                String name;
                if (path.length() == 0) {
                    // Special case for the Context Root mapping which is
                    // treated as an exact match
                    name = "/";
                } else {
                    name = path;
                }
                MappedWrapper[] oldWrappers = context.exactWrappers;
                if (oldWrappers.length == 0) {
                    return;
                }
                MappedWrapper[] newWrappers =
                    new MappedWrapper[oldWrappers.length - 1];
                if (removeMap(oldWrappers, newWrappers, name)) {
                    context.exactWrappers = newWrappers;
                }
            }
        }
    }


    /**添加welcomefile到context中
     * Add a welcome file to the given context.
     *
     * @param hostName
     * @param contextPath
     * @param welcomeFile
     */
    public void addWelcomeFile(String hostName, String contextPath,
            String version, String welcomeFile) {
        ContextVersion contextVersion = findContextVersion(hostName,
                contextPath, version, false);
        if (contextVersion == null) {
            return;
        }
        int len = contextVersion.welcomeResources.length + 1;
        String[] newWelcomeResources = new String[len];
        System.arraycopy(contextVersion.welcomeResources, 0,
                newWelcomeResources, 0, len - 1);
        newWelcomeResources[len - 1] = welcomeFile;
        contextVersion.welcomeResources = newWelcomeResources;
    }

    /**从context中删除welcome file
     * Remove a welcome file from the given context.
     *
     * @param hostName
     * @param contextPath
     * @param welcomeFile
     */
    public void removeWelcomeFile(String hostName, String contextPath,
            String version, String welcomeFile) {
        ContextVersion contextVersion = findContextVersion(hostName,
                contextPath, version, false);
        if (contextVersion == null || contextVersion.isPaused()) {
            return;
        }
        int match = -1;
        for (int i = 0; i < contextVersion.welcomeResources.length; i++) {
            if (welcomeFile.equals(contextVersion.welcomeResources[i])) {
                match = i;
                break;
            }
        }
        if (match > -1) {
            int len = contextVersion.welcomeResources.length - 1;
            String[] newWelcomeResources = new String[len];
            System.arraycopy(contextVersion.welcomeResources, 0,
                    newWelcomeResources, 0, match);
            if (match < len) {
                System.arraycopy(contextVersion.welcomeResources, match + 1,
                        newWelcomeResources, match, len - match);
            }
            contextVersion.welcomeResources = newWelcomeResources;
        }
    }

    /**从context中清除welcome file
     * Clear the welcome files for the given context.
     *
     * @param hostName
     * @param contextPath
     */
    public void clearWelcomeFiles(String hostName, String contextPath,
            String version) {
        ContextVersion contextVersion = findContextVersion(hostName,
                contextPath, version, false);
        if (contextVersion == null) {
            return;
        }
        contextVersion.welcomeResources = new String[0];
    }

    /**
     * 进行映射操作的函数(host-uri)
     * Map the specified host name and URI, mutating the given mapping data.
     *
     * @param host Virtual host name
     * @param uri URI
     * @param mappingData This structure will contain the result of the mapping
     *                    operation
     * @throws IOException if the buffers are too small to hold the results of
     *                     the mapping.
     */
    public void map(MessageBytes host, MessageBytes uri, String version,
                    MappingData mappingData) throws IOException {

        if (host.isNull()) {
            host.getCharChunk().append(defaultHostName);
        }
        host.toChars();
        uri.toChars();
        internalMap(host.getCharChunk(), uri.getCharChunk(), version,
                mappingData);

    }


    /**进行映射操作的函数(context-uri)
     * Map the specified URI relative to the context,
     * mutating the given mapping data.
     *
     * @param context The actual context
     * @param uri URI
     * @param mappingData This structure will contain the result of the mapping
     *                    operation
     * @throws IOException if the buffers are too small to hold the results of
     *                     the mapping.
     */
    public void map(Context context, MessageBytes uri,
            MappingData mappingData) throws IOException {

        ContextVersion contextVersion =
                contextObjectToContextVersionMap.get(context);
        uri.toChars();
        CharChunk uricc = uri.getCharChunk();
        uricc.setLimit(-1);
        internalMapWrapper(contextVersion, uricc, mappingData);

    }


    // -------------------------------------------------------- Private Methods


    /**
     * Map the specified URI.
     * @throws IOException
     */
    private final void internalMap(CharChunk host, CharChunk uri,
            String version, MappingData mappingData) throws IOException {

        if (mappingData.host != null) {
            // The legacy code (dating down at least to Tomcat 4.1) just
            // skipped all mapping work in this case. That behaviour has a risk
            // of returning an inconsistent result.
            // I do not see a valid use case for it.
            throw new AssertionError();
        }

        uri.setLimit(-1);

        // Virtual host mapping
        MappedHost[] hosts = this.hosts;
        //找到host
        MappedHost mappedHost = exactFindIgnoreCase(hosts, host);
        if (mappedHost == null) {
            if (defaultHostName == null) {
                return;
            }
            mappedHost = exactFind(hosts, defaultHostName);
            if (mappedHost == null) {
                return;
            }
        }
        mappingData.host = mappedHost.object;

        // host中的context列表
        ContextList contextList = mappedHost.contextList;
        MappedContext[] contexts = contextList.contexts;
        int pos = find(contexts, uri);
        if (pos == -1) {
            return;
        }

        int lastSlash = -1;
        int uriEnd = uri.getEnd();
        int length = -1;
        boolean found = false;
        //找到context
        MappedContext context = null;
        while (pos >= 0) {
            context = contexts[pos];
            if (uri.startsWith(context.name)) {
                length = context.name.length();
                if (uri.getLength() == length) {
                    found = true;
                    break;
                } else if (uri.startsWithIgnoreCase("/", length)) {
                    found = true;
                    break;
                }
            }
            if (lastSlash == -1) {
                lastSlash = nthSlash(uri, contextList.nesting + 1);
            } else {
                lastSlash = lastSlash(uri);
            }
            uri.setEnd(lastSlash);
            pos = find(contexts, uri);
        }
        uri.setEnd(uriEnd);

        if (!found) {
            if (contexts[0].name.equals("")) {
                context = contexts[0];
            } else {
                context = null;
            }
        }
        if (context == null) {
            return;
        }

        mappingData.contextPath.setString(context.name);

        ContextVersion contextVersion = null;
        ContextVersion[] contextVersions = context.versions;
        final int versionCount = contextVersions.length;
        if (versionCount > 1) {
            Context[] contextObjects = new Context[contextVersions.length];
            for (int i = 0; i < contextObjects.length; i++) {
                contextObjects[i] = contextVersions[i].object;
            }
            mappingData.contexts = contextObjects;
            if (version != null) {
                contextVersion = exactFind(contextVersions, version);
            }
        }
        if (contextVersion == null) {
            // Return the latest version
            // The versions array is known to contain at least one element
            contextVersion = contextVersions[versionCount - 1];
        }
        mappingData.context = contextVersion.object;
        mappingData.contextSlashCount = contextVersion.slashCount;

        // Wrapper mapping
        if (!contextVersion.isPaused()) {
            internalMapWrapper(contextVersion, uri, mappingData);
        }

    }


    /**
     * 映射Wrapper
     * Wrapper mapping.
     * @throws IOException if the buffers are too small to hold the results of
     *                     the mapping.
     */
    private final void internalMapWrapper(ContextVersion contextVersion,
                                          CharChunk path,
                                          MappingData mappingData) throws IOException {

        int pathOffset = path.getOffset();
        int pathEnd = path.getEnd();
        boolean noServletPath = false;

        int length = contextVersion.path.length();
        if (length == (pathEnd - pathOffset)) {
            noServletPath = true;
        }
        int servletPath = pathOffset + length;
        path.setOffset(servletPath);

        // Rule 1 -- Exact Match
        MappedWrapper[] exactWrappers = contextVersion.exactWrappers;
        internalMapExactWrapper(exactWrappers, path, mappingData);

        // Rule 2 -- Prefix Match
        boolean checkJspWelcomeFiles = false;
        MappedWrapper[] wildcardWrappers = contextVersion.wildcardWrappers;
        if (mappingData.wrapper == null) {
            internalMapWildcardWrapper(wildcardWrappers, contextVersion.nesting,
                                       path, mappingData);
            if (mappingData.wrapper != null && mappingData.jspWildCard) {
                char[] buf = path.getBuffer();
                if (buf[pathEnd - 1] == '/') {
                    /*
                     * Path ending in '/' was mapped to JSP servlet based on
                     * wildcard match (e.g., as specified in url-pattern of a
                     * jsp-property-group.
                     * Force the context's welcome files, which are interpreted
                     * as JSP files (since they match the url-pattern), to be
                     * considered. See Bugzilla 27664.
                     */
                    mappingData.wrapper = null;
                    checkJspWelcomeFiles = true;
                } else {
                    // See Bugzilla 27704
                    mappingData.wrapperPath.setChars(buf, path.getStart(),
                                                     path.getLength());
                    mappingData.pathInfo.recycle();
                }
            }
        }

        if(mappingData.wrapper == null && noServletPath &&
                contextVersion.object.getMapperContextRootRedirectEnabled()) {
            // The path is empty, redirect to "/"
            path.append('/');
            pathEnd = path.getEnd();
            mappingData.redirectPath.setChars
                (path.getBuffer(), pathOffset, pathEnd - pathOffset);
            path.setEnd(pathEnd - 1);
            return;
        }

        // Rule 3 -- Extension Match
        MappedWrapper[] extensionWrappers = contextVersion.extensionWrappers;
        if (mappingData.wrapper == null && !checkJspWelcomeFiles) {
            internalMapExtensionWrapper(extensionWrappers, path, mappingData,
                    true);
        }

        // Rule 4 -- Welcome resources processing for servlets
        if (mappingData.wrapper == null) {
            boolean checkWelcomeFiles = checkJspWelcomeFiles;
            if (!checkWelcomeFiles) {
                char[] buf = path.getBuffer();
                checkWelcomeFiles = (buf[pathEnd - 1] == '/');
            }
            if (checkWelcomeFiles) {
                for (int i = 0; (i < contextVersion.welcomeResources.length)
                         && (mappingData.wrapper == null); i++) {
                    path.setOffset(pathOffset);
                    path.setEnd(pathEnd);
                    path.append(contextVersion.welcomeResources[i], 0,
                            contextVersion.welcomeResources[i].length());
                    path.setOffset(servletPath);

                    // Rule 4a -- Welcome resources processing for exact macth
                    internalMapExactWrapper(exactWrappers, path, mappingData);

                    // Rule 4b -- Welcome resources processing for prefix match
                    if (mappingData.wrapper == null) {
                        internalMapWildcardWrapper
                            (wildcardWrappers, contextVersion.nesting,
                             path, mappingData);
                    }

                    // Rule 4c -- Welcome resources processing
                    //            for physical folder
                    if (mappingData.wrapper == null
                        && contextVersion.resources != null) {
                        String pathStr = path.toString();
                        WebResource file =
                                contextVersion.resources.getResource(pathStr);
                        if (file != null && file.isFile()) {
                            internalMapExtensionWrapper(extensionWrappers, path,
                                                        mappingData, true);
                            if (mappingData.wrapper == null
                                && contextVersion.defaultWrapper != null) {
                                mappingData.wrapper =
                                    contextVersion.defaultWrapper.object;
                                mappingData.requestPath.setChars
                                    (path.getBuffer(), path.getStart(),
                                     path.getLength());
                                mappingData.wrapperPath.setChars
                                    (path.getBuffer(), path.getStart(),
                                     path.getLength());
                                mappingData.requestPath.setString(pathStr);
                                mappingData.wrapperPath.setString(pathStr);
                            }
                        }
                    }
                }

                path.setOffset(servletPath);
                path.setEnd(pathEnd);
            }

        }

        /* welcome file processing - take 2
         * Now that we have looked for welcome files with a physical
         * backing, now look for an extension mapping listed
         * but may not have a physical backing to it. This is for
         * the case of index.jsf, index.do, etc.
         * A watered down version of rule 4
         */
        if (mappingData.wrapper == null) {
            boolean checkWelcomeFiles = checkJspWelcomeFiles;
            if (!checkWelcomeFiles) {
                char[] buf = path.getBuffer();
                checkWelcomeFiles = (buf[pathEnd - 1] == '/');
            }
            if (checkWelcomeFiles) {
                for (int i = 0; (i < contextVersion.welcomeResources.length)
                         && (mappingData.wrapper == null); i++) {
                    path.setOffset(pathOffset);
                    path.setEnd(pathEnd);
                    path.append(contextVersion.welcomeResources[i], 0,
                                contextVersion.welcomeResources[i].length());
                    path.setOffset(servletPath);
                    internalMapExtensionWrapper(extensionWrappers, path,
                                                mappingData, false);
                }

                path.setOffset(servletPath);
                path.setEnd(pathEnd);
            }
        }


        // Rule 7 -- Default servlet
        if (mappingData.wrapper == null && !checkJspWelcomeFiles) {
            if (contextVersion.defaultWrapper != null) {
                mappingData.wrapper = contextVersion.defaultWrapper.object;
                mappingData.requestPath.setChars
                    (path.getBuffer(), path.getStart(), path.getLength());
                mappingData.wrapperPath.setChars
                    (path.getBuffer(), path.getStart(), path.getLength());
            }
            // Redirection to a folder
            char[] buf = path.getBuffer();
            if (contextVersion.resources != null && buf[pathEnd -1 ] != '/') {
                String pathStr = path.toString();
                WebResource file;
                // Handle context root
                if (pathStr.length() == 0) {
                    file = contextVersion.resources.getResource("/");
                } else {
                    file = contextVersion.resources.getResource(pathStr);
                }
                if (file != null && file.isDirectory() &&
                        contextVersion.object.getMapperDirectoryRedirectEnabled()) {
                    // Note: this mutates the path: do not do any processing
                    // after this (since we set the redirectPath, there
                    // shouldn't be any)
                    path.setOffset(pathOffset);
                    path.append('/');
                    mappingData.redirectPath.setChars
                        (path.getBuffer(), path.getStart(), path.getLength());
                } else {
                    mappingData.requestPath.setString(pathStr);
                    mappingData.wrapperPath.setString(pathStr);
                }
            }
        }

        path.setOffset(pathOffset);
        path.setEnd(pathEnd);
    }


    /**ExactWrapper进行匹配
     * Exact mapping.
     */
    private final void internalMapExactWrapper
        (MappedWrapper[] wrappers, CharChunk path, MappingData mappingData) {
        MappedWrapper wrapper = exactFind(wrappers, path);
        if (wrapper != null) {
            mappingData.requestPath.setString(wrapper.name);
            mappingData.wrapper = wrapper.object;
            if (path.equals("/")) {
                // Special handling for Context Root mapped servlet
                mappingData.pathInfo.setString("/");
                mappingData.wrapperPath.setString("");
                // This seems wrong but it is what the spec says...
                mappingData.contextPath.setString("");
            } else {
                mappingData.wrapperPath.setString(wrapper.name);
            }
        }
    }


    /**
     * Wildcard mapping.
     */
    private final void internalMapWildcardWrapper
        (MappedWrapper[] wrappers, int nesting, CharChunk path,
         MappingData mappingData) {

        int pathEnd = path.getEnd();

        int lastSlash = -1;
        int length = -1;
        int pos = find(wrappers, path);
        if (pos != -1) {
            boolean found = false;
            while (pos >= 0) {
                if (path.startsWith(wrappers[pos].name)) {
                    length = wrappers[pos].name.length();
                    if (path.getLength() == length) {
                        found = true;
                        break;
                    } else if (path.startsWithIgnoreCase("/", length)) {
                        found = true;
                        break;
                    }
                }
                if (lastSlash == -1) {
                    lastSlash = nthSlash(path, nesting + 1);
                } else {
                    lastSlash = lastSlash(path);
                }
                path.setEnd(lastSlash);
                pos = find(wrappers, path);
            }
            path.setEnd(pathEnd);
            if (found) {
                mappingData.wrapperPath.setString(wrappers[pos].name);
                if (path.getLength() > length) {
                    mappingData.pathInfo.setChars
                        (path.getBuffer(),
                         path.getOffset() + length,
                         path.getLength() - length);
                }
                mappingData.requestPath.setChars
                    (path.getBuffer(), path.getOffset(), path.getLength());
                mappingData.wrapper = wrappers[pos].object;
                mappingData.jspWildCard = wrappers[pos].jspWildCard;
            }
        }
    }


    /**
     * Extension mappings.
     *
     * @param wrappers          Set of wrappers to check for matches
     * @param path              Path to map
     * @param mappingData       Mapping data for result
     * @param resourceExpected  Is this mapping expecting to find a resource
     */
    private final void internalMapExtensionWrapper(MappedWrapper[] wrappers,
            CharChunk path, MappingData mappingData, boolean resourceExpected) {
        char[] buf = path.getBuffer();
        int pathEnd = path.getEnd();
        int servletPath = path.getOffset();
        int slash = -1;
        for (int i = pathEnd - 1; i >= servletPath; i--) {
            if (buf[i] == '/') {
                slash = i;
                break;
            }
        }
        if (slash >= 0) {
            int period = -1;
            for (int i = pathEnd - 1; i > slash; i--) {
                if (buf[i] == '.') {
                    period = i;
                    break;
                }
            }
            if (period >= 0) {
                path.setOffset(period + 1);
                path.setEnd(pathEnd);
                MappedWrapper wrapper = exactFind(wrappers, path);
                if (wrapper != null
                        && (resourceExpected || !wrapper.resourceOnly)) {
                    mappingData.wrapperPath.setChars(buf, servletPath, pathEnd
                            - servletPath);
                    mappingData.requestPath.setChars(buf, servletPath, pathEnd
                            - servletPath);
                    mappingData.wrapper = wrapper.object;
                }
                path.setOffset(servletPath);
                path.setEnd(pathEnd);
            }
        }
    }


    /**
     * Find a map element given its name in a sorted array of map elements.
     * This will return the index for the closest inferior or equal item in the
     * given array.
     */
    private static final <T> int find(MapElement<T>[] map, CharChunk name) {
        return find(map, name, name.getStart(), name.getEnd());
    }


    /**
     * Find a map element given its name in a sorted array of map elements.
     * This will return the index for the closest inferior or equal item in the
     * given array.
     */
    private static final <T> int find(MapElement<T>[] map, CharChunk name,
                                  int start, int end) {

        int a = 0;
        int b = map.length - 1;

        // Special cases: -1 and 0
        if (b == -1) {
            return -1;
        }

        if (compare(name, start, end, map[0].name) < 0 ) {
            return -1;
        }
        if (b == 0) {
            return 0;
        }

        int i = 0;
        while (true) {
            i = (b + a) / 2;
            int result = compare(name, start, end, map[i].name);
            if (result == 1) {
                a = i;
            } else if (result == 0) {
                return i;
            } else {
                b = i;
            }
            if ((b - a) == 1) {
                int result2 = compare(name, start, end, map[b].name);
                if (result2 < 0) {
                    return a;
                } else {
                    return b;
                }
            }
        }

    }

    /**
     * Find a map element given its name in a sorted array of map elements.
     * This will return the index for the closest inferior or equal item in the
     * given array.
     */
    private static final <T> int findIgnoreCase(MapElement<T>[] map, CharChunk name) {
        return findIgnoreCase(map, name, name.getStart(), name.getEnd());
    }


    /**
     * Find a map element given its name in a sorted array of map elements.
     * This will return the index for the closest inferior or equal item in the
     * given array.
     */
    private static final <T> int findIgnoreCase(MapElement<T>[] map, CharChunk name,
                                  int start, int end) {

        int a = 0;
        int b = map.length - 1;

        // Special cases: -1 and 0
        if (b == -1) {
            return -1;
        }
        if (compareIgnoreCase(name, start, end, map[0].name) < 0 ) {
            return -1;
        }
        if (b == 0) {
            return 0;
        }

        int i = 0;
        while (true) {
            i = (b + a) / 2;
            int result = compareIgnoreCase(name, start, end, map[i].name);
            if (result == 1) {
                a = i;
            } else if (result == 0) {
                return i;
            } else {
                b = i;
            }
            if ((b - a) == 1) {
                int result2 = compareIgnoreCase(name, start, end, map[b].name);
                if (result2 < 0) {
                    return a;
                } else {
                    return b;
                }
            }
        }

    }


    /**
     * Find a map element given its name in a sorted array of map elements.
     * This will return the index for the closest inferior or equal item in the
     * given array.
     * @see #exactFind(MapElement[], String)
     * 因为是有序的所以采用了二分搜索的技术搜索插入位置
     */
    private static final <T> int find(MapElement<T>[] map, String name) {

        int a = 0;
        int b = map.length - 1;

        // Special cases: -1 and 0
        if (b == -1) {
            return -1;
        }

        if (name.compareTo(map[0].name) < 0) {
            return -1;
        }
        if (b == 0) {
            return 0;
        }

        int i = 0;
        while (true) {
            i = (b + a) / 2;
            int result = name.compareTo(map[i].name);
            if (result > 0) {
                a = i;
            } else if (result == 0) {
                return i;
            } else {
                b = i;
            }
            if ((b - a) == 1) {
                int result2 = name.compareTo(map[b].name);
                if (result2 < 0) {
                    return a;
                } else {
                    return b;
                }
            }
        }

    }


    /**
     * Find a map element given its name in a sorted array of map elements. This
     * will return the element that you were searching for. Otherwise it will
     * return <code>null</code>.
     * @see #find(MapElement[], String)
     */
    private static final <T, E extends MapElement<T>> E exactFind(E[] map,
            String name) {
    	//找到元素的位置
        int pos = find(map, name);
        if (pos >= 0) {
            E result = map[pos];
            if (name.equals(result.name)) {
                return result;
            }
        }
        return null;
    }

    /**
     * Find a map element given its name in a sorted array of map elements. This
     * will return the element that you were searching for. Otherwise it will
     * return <code>null</code>.
     */
    private static final <T, E extends MapElement<T>> E exactFind(E[] map,
            CharChunk name) {
        int pos = find(map, name);
        if (pos >= 0) {
            E result = map[pos];
            if (name.equals(result.name)) {
                return result;
            }
        }
        return null;
    }

    /**
     * Find a map element given its name in a sorted array of map elements. This
     * will return the element that you were searching for. Otherwise it will
     * return <code>null</code>.
     * @see #findIgnoreCase(MapElement[], CharChunk)
     */
    private static final <T, E extends MapElement<T>> E exactFindIgnoreCase(
            E[] map, CharChunk name) {
        int pos = findIgnoreCase(map, name);
        if (pos >= 0) {
            E result = map[pos];
            if (name.equalsIgnoreCase(result.name)) {
                return result;
            }
        }
        return null;
    }


    /**
     * Compare given char chunk with String.
     * Return -1, 0 or +1 if inferior, equal, or superior to the String.
     */
    private static final int compare(CharChunk name, int start, int end,
                                     String compareTo) {
        int result = 0;
        char[] c = name.getBuffer();
        int len = compareTo.length();
        if ((end - start) < len) {
            len = end - start;
        }
        for (int i = 0; (i < len) && (result == 0); i++) {
            if (c[i + start] > compareTo.charAt(i)) {
                result = 1;
            } else if (c[i + start] < compareTo.charAt(i)) {
                result = -1;
            }
        }
        if (result == 0) {
            if (compareTo.length() > (end - start)) {
                result = -1;
            } else if (compareTo.length() < (end - start)) {
                result = 1;
            }
        }
        return result;
    }


    /**
     * Compare given char chunk with String ignoring case.
     * Return -1, 0 or +1 if inferior, equal, or superior to the String.
     */
    private static final int compareIgnoreCase(CharChunk name, int start, int end,
                                     String compareTo) {
        int result = 0;
        char[] c = name.getBuffer();
        int len = compareTo.length();
        if ((end - start) < len) {
            len = end - start;
        }
        //逐个字节比较
        for (int i = 0; (i < len) && (result == 0); i++) {
            if (Ascii.toLower(c[i + start]) > Ascii.toLower(compareTo.charAt(i))) {
                result = 1;
            } else if (Ascii.toLower(c[i + start]) < Ascii.toLower(compareTo.charAt(i))) {
                result = -1;
            }
        }
        if (result == 0) {
        	//比较长度了
            if (compareTo.length() > (end - start)) {
                result = -1;
            } else if (compareTo.length() < (end - start)) {
                result = 1;
            }
        }
        return result;
    }


    /**
     * Find the position of the last slash in the given char chunk.
     */
    private static final int lastSlash(CharChunk name) {

        char[] c = name.getBuffer();
        int end = name.getEnd();
        int start = name.getStart();
        int pos = end;

        while (pos > start) {
            if (c[--pos] == '/') {
                break;
            }
        }

        return (pos);

    }


    /**
     * Find the position of the nth slash, in the given char chunk.
     */
    private static final int nthSlash(CharChunk name, int n) {

        char[] c = name.getBuffer();
        int end = name.getEnd();
        int start = name.getStart();
        int pos = start;
        int count = 0;

        while (pos < end) {
            if ((c[pos++] == '/') && ((++count) == n)) {
                pos--;
                break;
            }
        }

        return (pos);

    }


    /**
     * Return the slash count in a given string.统计'/'的数量
     */
    private static final int slashCount(String name) {
        int pos = -1;
        int count = 0;
        while ((pos = name.indexOf('/', pos + 1)) != -1) {
            count++;
        }
        return count;
    }


    /**
     * Insert into the right place in a sorted MapElement array, and prevent
     * duplicates.
     * 在有序的map中正确的插入,因为里面使用了二分的搜索算法所以是有序的map
     */
    private static final <T> boolean insertMap
        (MapElement<T>[] oldMap, MapElement<T>[] newMap, MapElement<T> newElement) {
    	//找到插入位置,采用了二分搜索技术
        int pos = find(oldMap, newElement.name);
        //已经有相同的元素了,不用插入
        if ((pos != -1) && (newElement.name.equals(oldMap[pos].name))) {
            return false;
        }
        //将老数组的内容复制到新数组,从开始到插入位置
        System.arraycopy(oldMap, 0, newMap, 0, pos + 1);
        //插入新的元素
        newMap[pos + 1] = newElement;
        //将老数组的内容复制到新数组,从插入位置后面到最后的位置
        System.arraycopy
            (oldMap, pos + 1, newMap, pos + 2, oldMap.length - pos - 1);
        return true;
    }


    /**
     * Insert into the right place in a sorted MapElement array.
     * 删除有序map中的一个元素
     */
    private static final <T> boolean removeMap
        (MapElement<T>[] oldMap, MapElement<T>[] newMap, String name) {
    	//根据二分法找到要删除元素的位置
        int pos = find(oldMap, name);
        if ((pos != -1) && (name.equals(oldMap[pos].name))) {
        	//将要删除元素前面的元素和后面的元素拷贝过去
            System.arraycopy(oldMap, 0, newMap, 0, pos);
            System.arraycopy(oldMap, pos + 1, newMap, pos,
                             oldMap.length - pos - 1);
            return true;
        }
        return false;
    }


    // ------------------------------------------------- MapElement Inner Class

    //基础键值对模型,name为容器名称,object为容器
    protected abstract static class MapElement<T> {

        public final String name;
        public final T object;

        public MapElement(String name, T object) {
            this.name = name;
            this.object = object;
        }
    }


    // ------------------------------------------------------- Host Inner Class

    //这个类就是host映射模型,里面包含若干个Context,ContextList就是一个包含若干Context的对象
    //Host是一Host容器类型,一个接口,有具体的实现类
    protected static final class MappedHost extends MapElement<Host> {

        public volatile ContextList contextList;

        /**
         * 真正的MappedHost对象,被所有alias共享的
         * Link to the "real" MappedHost, shared by all aliases.
         */
        private final MappedHost realHost;

        /**
         * Links to all registered aliases, for easy enumeration. This field
         * is available only in the "real" MappedHost. In an alias this field
         * is <code>null</code>.
         */
        private final List<MappedHost> aliases;

        /**
         * Constructor used for the primary Host
         */
        public MappedHost(String name, Host host) {
            super(name, host);
            realHost = this;
            contextList = new ContextList();
            aliases = new CopyOnWriteArrayList<>();
        }

        /**
         * Constructor used for an Alias
         */
        public MappedHost(String alias, MappedHost realHost) {
            super(alias, realHost.object);
            this.realHost = realHost;
            this.contextList = realHost.contextList;
            this.aliases = null;
        }

        public boolean isAlias() {
            return realHost != this;
        }

        public MappedHost getRealHost() {
            return realHost;
        }

        public String getRealHostName() {
            return realHost.name;
        }

        public Collection<MappedHost> getAliases() {
            return aliases;
        }

        public void addAlias(MappedHost alias) {
            aliases.add(alias);
        }

        public void addAliases(Collection<? extends MappedHost> c) {
            aliases.addAll(c);
        }

        public void removeAlias(MappedHost alias) {
            aliases.remove(alias);
        }
    }


    // ------------------------------------------------ ContextList Inner Class

    //用于存放多个Context(MappedContext)
    protected static final class ContextList {

        public final MappedContext[] contexts;
        public final int nesting;

        public ContextList() {
            this(new MappedContext[0], 0);
        }

        private ContextList(MappedContext[] contexts, int nesting) {
            this.contexts = contexts;
            this.nesting = nesting;
        }

        //添加Context
        public ContextList addContext(MappedContext mappedContext,
                int slashCount) {
            MappedContext[] newContexts = new MappedContext[contexts.length + 1];
            if (insertMap(contexts, newContexts, mappedContext)) {
                return new ContextList(newContexts, Math.max(nesting,
                        slashCount));
            }
            return null;
        }

        //删除Context
        public ContextList removeContext(String path) {
            MappedContext[] newContexts = new MappedContext[contexts.length - 1];
            if (removeMap(contexts, newContexts, path)) {
                int newNesting = 0;
                for (MappedContext context : newContexts) {
                    newNesting = Math.max(newNesting, slashCount(context.name));
                }
                return new ContextList(newContexts, newNesting);
            }
            return null;
        }
    }


    // ---------------------------------------------------- Context Inner Class


    //提供Context映射模型,在其中包含若干个Wrapper,ContextVersion就是一个包含若干个Wrapper的对象.
    protected static final class MappedContext extends MapElement<Void> {
        public volatile ContextVersion[] versions;

        public MappedContext(String name, ContextVersion firstVersion) {
            super(name, null);
            this.versions = new ContextVersion[] { firstVersion };
        }
    }

    //Context映射模型,继承MapElement,包含不同类型的Mapper:默认Servlet,精确匹配servlet,通配符Servlet,扩展Servlet
    protected static final class ContextVersion extends MapElement<Context> {
        public final String path;
        public final int slashCount;
        public final WebResourceRoot resources;
        public String[] welcomeResources;
        //默认Servlet
        public MappedWrapper defaultWrapper = null;
        //精确匹配servlet
        public MappedWrapper[] exactWrappers = new MappedWrapper[0];
        //通配符Servlet
        public MappedWrapper[] wildcardWrappers = new MappedWrapper[0];
        //扩展Servlet
        public MappedWrapper[] extensionWrappers = new MappedWrapper[0];
        public int nesting = 0;
        private volatile boolean paused;

        public ContextVersion(String version, String path, int slashCount,
                Context context, WebResourceRoot resources,
                String[] welcomeResources) {
            super(version, context);
            this.path = path;
            this.slashCount = slashCount;
            this.resources = resources;
            this.welcomeResources = welcomeResources;
        }

        public boolean isPaused() {
            return paused;
        }

        public void markPaused() {
            paused = true;
        }
    }

    // ---------------------------------------------------- Wrapper Inner Class

    //Wrapper映射模型
    protected static class MappedWrapper extends MapElement<Wrapper> {

        public final boolean jspWildCard;
        public final boolean resourceOnly;

        public MappedWrapper(String name, Wrapper wrapper, boolean jspWildCard,
                boolean resourceOnly) {
            super(name, wrapper);
            this.jspWildCard = jspWildCard;
            this.resourceOnly = resourceOnly;
        }
    }
}
