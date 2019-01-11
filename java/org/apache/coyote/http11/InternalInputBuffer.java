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
package org.apache.coyote.http11;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import org.apache.coyote.InputBuffer;
import org.apache.coyote.Request;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.parser.HttpParser;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SocketWrapper;

/**
 * Implementation of InputBuffer which provides HTTP request header parsing as
 * well as transfer decoding.
 *
 * @author <a href="mailto:remm@apache.org">Remy Maucherat</a>
 */
public class InternalInputBuffer extends AbstractInputBuffer<Socket> {

	private static final Log log = LogFactory.getLog(InternalInputBuffer.class);


	/**
	 * Underlying input stream.
	 */
	private InputStream inputStream;


	/**
	 * Default constructor.
	 */
	public InternalInputBuffer(Request request, int headerBufferSize,
			boolean rejectIllegalHeaderName) {

		this.request = request;
		headers = request.getMimeHeaders();

		buf = new byte[headerBufferSize];

		this.rejectIllegalHeaderName = rejectIllegalHeaderName;

		inputStreamInputBuffer = new InputStreamInputBuffer();

		filterLibrary = new InputFilter[0];
		activeFilters = new InputFilter[0];
		lastActiveFilter = -1;

		parsingHeader = true;
		swallowInput = true;

	}


	/**
	 * Data is always available for blocking IO (if you wait long enough) so
	 * return a value of 1. Note that the actual value is never used it is only
	 * tested for == 0 or &gt; 0.
	 */
	@Override
	public int available(boolean read) {
		return 1;
	}


	/**
	 * 解析HTTP请求行(最上面那一行包括 请求方法  URI 协议版本)
	 * Read the request line. This function is meant to be used during the
	 * HTTP request header parsing. Do NOT attempt to read the request body
	 * using it.
	 *
	 * @throws IOException If an exception occurs during the underlying socket
	 * read operations, or if the given buffer is not big enough to accommodate
	 * the whole line.
	 */
	@Override
	public boolean parseRequestLine(boolean useAvailableDataOnly)

			throws IOException {

		int start = 0;

		//
		// Skipping blank lines
		//

		byte chr = 0;
		do {

			// Read new bytes if needed
			if (pos >= lastValid) {
				if (!fill())
					throw new EOFException(sm.getString("iib.eof.error"));
			}
			// Set the start time once we start reading data (even if it is
			// just skipping blank lines)
			if (request.getStartTime() < 0) {
				request.setStartTime(System.currentTimeMillis());
			}
			chr = buf[pos++];
		} while ((chr == Constants.CR) || (chr == Constants.LF));

		pos--;

		// Mark the current buffer position
		start = pos;

		//
		// Reading the method name
		// Method name is a token
		//

		boolean space = false;
		// 这个while循环用于解析请求方法名,每次操作前必须判断是否需要从底层读取字节流,
		//当pos大于lastVaild时,需要调用fill方法读取.
		while (!space) {

			// Read new bytes if needed
			if (pos >= lastValid) {
				if (!fill())
					throw new EOFException(sm.getString("iib.eof.error"));
			}

			// Spec says method name is a token followed by a single SP but
			// also be tolerant of multiple SP and/or HT.
			//当字节等于ASCII编码的空格时就截取start到pos之间的字节数组,这便是方法名的组成,解析完成后设置到request中
			if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
				space = true;
				request.method().setBytes(buf, start, pos - start);
			} else if (!HttpParser.isToken(buf[pos])) {
				throw new IllegalArgumentException(sm.getString("iib.invalidmethod"));
			}

			pos++;

		}

		// Spec says single SP but also be tolerant of multiple SP and/or HT
		//这个while循环用于跳过请求方法名和URI之间所有的空格,同样解析之前需要判断是否要
		//从底层读取字节流
		while (space) {
			// Read new bytes if needed
			if (pos >= lastValid) {
				if (!fill())
					throw new EOFException(sm.getString("iib.eof.error"));
			}
			if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
				pos++;
			} else {
				space = false;
			}
		}

		// Mark the current buffer position
		start = pos;
		int end = 0;
		int questionPos = -1;

		//
		// Reading the URI
		//

		boolean eol = false;
		//这个while循环用于解析URI,每次都要判断是否需要从底层读取字节流
		while (!space) {

			// Read new bytes if needed
			if (pos >= lastValid) {
				if (!fill())
					throw new EOFException(sm.getString("iib.eof.error"));
			}

			// Spec says single SP but it also says be tolerant of HT
			//同样根据http请求的协议可知,根据空格来截取URI
			if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
				space = true;
				end = pos;
			} else if ((buf[pos] == Constants.CR)
					|| (buf[pos] == Constants.LF)) {
				// HTTP/0.9 style request
				eol = true;
				space = true;
				end = pos;
				//如果解析到问号
			} else if ((buf[pos] == Constants.QUESTION) && (questionPos == -1)) {
				questionPos = pos;
			} else if (HttpParser.isNotRequestTarget(buf[pos])) {
				throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget"));
			}

			pos++;

		}
		//有请求参数,因为解析到了问号
		if (questionPos >= 0) {
			//设置请求参数
			request.queryString().setBytes(buf, questionPos + 1,
					end - questionPos - 1);
			//设置URI
			request.requestURI().setBytes(buf, start, questionPos - start);
		} else {
			request.requestURI().setBytes(buf, start, end - start);
		}

		// Spec says single SP but also says be tolerant of multiple SP and/or HT
		//这个while循环用于跳过URI和协议版本之间所有的空格,同样解析之前需要判断是否要
		//从底层读取字节流
		while (space) {
			// Read new bytes if needed
			if (pos >= lastValid) {
				if (!fill())
					throw new EOFException(sm.getString("iib.eof.error"));
			}
			if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
				pos++;
			} else {
				space = false;
			}
		}

		// Mark the current buffer position
		start = pos;
		end = 0;

		//
		// Reading the protocol
		// Protocol is always "HTTP/" DIGIT "." DIGIT
		//
		while (!eol) {

			// Read new bytes if needed
			if (pos >= lastValid) {
				if (!fill())
					throw new EOFException(sm.getString("iib.eof.error"));
			}

			if (buf[pos] == Constants.CR) {
				end = pos;
			} else if (buf[pos] == Constants.LF) {
				if (end == 0)
					end = pos;
				eol = true;
			} else if (!HttpParser.isHttpProtocol(buf[pos])) {
				throw new IllegalArgumentException(sm.getString("iib.invalidHttpProtocol"));
			}

			pos++;

		}

		if ((end - start) > 0) {
			request.protocol().setBytes(buf, start, end - start);
		} else {
			request.protocol().setString("");
		}

		return true;

	}


	/**
	 * 解析HTTP请求头 
	 * Parse the HTTP headers.
	 */
	@Override
	public boolean parseHeaders()
			throws IOException {
		if (!parsingHeader) {
			throw new IllegalStateException(
					sm.getString("iib.parseheaders.ise.error"));
		}
		//一直循环解析,直到跳出header(遇到空行)
		while (parseHeader()) {
			// Loop until we run out of headers
		}

		parsingHeader = false;
		end = pos;
		return true;
	}


	/**
	 * 解析HTTP请求头
	 * Parse an HTTP header.
	 *
	 * @return false after reading a blank line (which indicates that the
	 * HTTP header parsing is done
	 */
	@SuppressWarnings("null") // headerValue cannot be null
	private boolean parseHeader()
			throws IOException {

		byte chr = 0;
		//检测空行
		while (true) {

			//每次解析之前需要判断是否读取底层字节流字节
			if (pos >= lastValid) {
				if (!fill())
					throw new EOFException(sm.getString("iib.eof.error"));
			}

			chr = buf[pos];
			//要首先判断开头的是不是\r\n.如果开头就是\r\n说明是空行
			//判断当前字节是否是\r
			if (chr == Constants.CR) {
				// Skip
			//判断当前字节是否是\n,\r和\n都代表换行,解析到空行说明http请求头结束了,返回false
			} else if (chr == Constants.LF) {
				pos++;
				return false;
			} else {
				break;
			}
			pos++;
		}

		// Mark the current buffer position
		//标记当前位置
		int start = pos;

		//
		// Reading the header name
		// Header name is always US-ASCII
		//

		boolean colon = false;
		MessageBytes headerValue = null;
		//解析字段名
		while (!colon) {

			//每次解析之前需要判断是否读取底层字节流字节
			if (pos >= lastValid) {
				if (!fill())
					throw new EOFException(sm.getString("iib.eof.error"));
			}

			//判断是否等于:(字段名:字段值)
			if (buf[pos] == Constants.COLON) {
				colon = true;
				//添加键值对的键
				headerValue = headers.addValue(buf, start, pos - start);
			//解析到非法字符
			} else if (!HttpParser.isToken(buf[pos])) {
				// Non-token characters are illegal in header names
				// Parsing continues so the error can be reported in context
				// skipLine() will handle the error
				skipLine(start);
				return true;
			}

			chr = buf[pos];
			if ((chr >= Constants.A) && (chr <= Constants.Z)) {
				buf[pos] = (byte) (chr - Constants.LC_OFFSET);
			}

			pos++;

		}

		// Mark the current buffer position
		start = pos;
		int realPos = pos;

		//
		// Reading the header value (which can be spanned over multiple lines)
		//
		//解析字段值
		boolean eol = false;
		boolean validLine = true;

		while (validLine) {

			boolean space = true;

			//跳过空格
			while (space) {

				//每次解析之前需要判断是否读取底层字节流字节
				if (pos >= lastValid) {
					if (!fill())
						throw new EOFException(sm.getString("iib.eof.error"));
				}

				if ((buf[pos] == Constants.SP) || (buf[pos] == Constants.HT)) {
					pos++;
				} else {
					space = false;
				}

			}

			int lastSignificantChar = realPos;

			//不到行结尾就继续循环
			while (!eol) {

				//每次解析之前需要判断是否读取底层字节流字节
				if (pos >= lastValid) {
					if (!fill())
						throw new EOFException(sm.getString("iib.eof.error"));
				}
				
				//如果是换行\r\n就结束while循环
				if (buf[pos] == Constants.CR) {
					// Skip
				} else if (buf[pos] == Constants.LF) {
					eol = true;
				} else if (buf[pos] == Constants.SP) {
					buf[realPos] = buf[pos];
					realPos++;
				} else {
					buf[realPos] = buf[pos];
					realPos++;
					lastSignificantChar = realPos;
				}

				pos++;

			}

			realPos = lastSignificantChar;

			// Checking the first character of the new line. If the character
			// is a LWS, then it's a multiline header

			// Read new bytes if needed
			if (pos >= lastValid) {
				if (!fill())
					throw new EOFException(sm.getString("iib.eof.error"));
			}

			chr = buf[pos];
			if ((chr != Constants.SP) && (chr != Constants.HT)) {
				validLine = false;
			} else {
				eol = false;
				// Copying one extra space in the buffer (since there must
				// be at least one space inserted between the lines)
				buf[realPos] = chr;
				realPos++;
			}

		}

		// 设置字段值
		headerValue.setBytes(buf, start, realPos - start);

		return true;

	}


	@Override
	public void recycle() {
		super.recycle();
		inputStream = null;
	}


	// ------------------------------------------------------ Protected Methods


	@Override
	protected void init(SocketWrapper<Socket> socketWrapper,
			AbstractEndpoint<Socket> endpoint) throws IOException {
		inputStream = socketWrapper.getSocket().getInputStream();
	}



	private void skipLine(int start) throws IOException {
		boolean eol = false;
		int lastRealByte = start;
		if (pos - 1 > start) {
			lastRealByte = pos - 1;
		}

		while (!eol) {

			// Read new bytes if needed
			if (pos >= lastValid) {
				if (!fill())
					throw new EOFException(sm.getString("iib.eof.error"));
			}

			if (buf[pos] == Constants.CR) {
				// Skip
			} else if (buf[pos] == Constants.LF) {
				eol = true;
			} else {
				lastRealByte = pos;
			}
			pos++;
		}

		if (rejectIllegalHeaderName || log.isDebugEnabled()) {
			String message = sm.getString("iib.invalidheader", new String(buf, start,
					lastRealByte - start + 1, StandardCharsets.ISO_8859_1));
			if (rejectIllegalHeaderName) {
				throw new IllegalArgumentException(message);
			}
			log.debug(message);
		}
	}

	/**
	 * Fill the internal buffer using data from the underlying input stream.
	 *
	 * @return false if at end of stream
	 */
	protected boolean fill() throws IOException {
		return fill(true);
	}

	@Override
	protected boolean fill(boolean block) throws IOException {

		int nRead = 0;

		if (parsingHeader) {

			if (lastValid == buf.length) {
				throw new IllegalArgumentException
				(sm.getString("iib.requestheadertoolarge.error"));
			}

			nRead = inputStream.read(buf, pos, buf.length - lastValid);
			if (nRead > 0) {
				lastValid = pos + nRead;
			}

		} else {

			if (buf.length - end < 4500) {
				// In this case, the request header was really large, so we allocate a
				// brand new one; the old one will get GCed when subsequent requests
				// clear all references
				buf = new byte[buf.length];
				end = 0;
			}
			pos = end;
			lastValid = pos;
			nRead = inputStream.read(buf, pos, buf.length - lastValid);
			if (nRead > 0) {
				lastValid = pos + nRead;
			}

		}

		return (nRead > 0);

	}


	@Override
	protected final Log getLog() {
		return log;
	}


	// ------------------------------------- InputStreamInputBuffer Inner Class

	/**
	 * This class is an input buffer which will read its data from an input
	 * stream.
	 */
	protected class InputStreamInputBuffer
	implements InputBuffer {


		/**
		 * Read bytes into the specified chunk.
		 */
		@Override
		public int doRead(ByteChunk chunk, Request req )
				throws IOException {

			if (pos >= lastValid) {
				if (!fill())
					return -1;
			}

			int length = lastValid - pos;
			chunk.setBytes(buf, pos, length);
			pos = lastValid;

			return (length);
		}
	}
}
