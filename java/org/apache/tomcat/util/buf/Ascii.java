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
package org.apache.tomcat.util.buf;

/**
 * This class implements some basic ASCII character handling functions.
 *
 * @author dac@eng.sun.com
 * @author James Todd [gonzo@eng.sun.com]
 */
public final class Ascii {
    /*
     * Character translation tables.
     */
    private static final byte[] toLower = new byte[256];

    /*
     * Character type tables.
     */
    private static final boolean[] isDigit = new boolean[256];

    private static final long OVERFLOW_LIMIT = Long.MAX_VALUE / 10;

    /*
     * Initialize character translation and type tables.
     */
    static {
        for (int i = 0; i < 256; i++) {
            toLower[i] = (byte)i;
        }
        //将大写转换为小写 
        for (int lc = 'a'; lc <= 'z'; lc++) {
            int uc = lc + 'A' - 'a';
//            System.out.println(lc);
            toLower[uc] = (byte)lc;
        }

        for (int d = '0'; d <= '9'; d++) {
            isDigit[d] = true;
        }
    }

    /**
     * 返回小写的asc码,自由字母有小写,别的没有小写
     * Returns the lower case equivalent of the specified ASCII character.
     */

    public static int toLower(int c) {
        return toLower[c & 0xff] & 0xff;
    }

    /**
     * 判断是否是数字
     * Returns true if the specified ASCII character is a digit.
     */
    private static boolean isDigit(int c) {
        return isDigit[c & 0xff];
    }

    /**
     * 将字节数组转化为整数
     * Parses an unsigned long from the specified subarray of bytes.
     * @param b the bytes to parse
     * @param off the start offset of the bytes
     * @param len the length of the bytes
     * @exception NumberFormatException if the long format was invalid
     */
    public static long parseLong(byte[] b, int off, int len)
        throws NumberFormatException
    {
        int c;

        if (b == null || len <= 0 || !isDigit(c = b[off++])) {
            throw new NumberFormatException();
        }

        long n = c - '0';
        while (--len > 0) {
            if (isDigit(c = b[off++]) &&
                    (n < OVERFLOW_LIMIT || (n == OVERFLOW_LIMIT && (c - '0') < 8))) {
                n = n * 10 + c - '0';
            } else {
                throw new NumberFormatException();
            }
        }

        return n;
    }
    
    public static void main(String[] args) {
		for(int i=0;i<256;i++) {
			if(i%20==0) {
				System.out.println();
			}
			System.out.print(toLower[i]+"  ");
		}
		System.out.println("-----------------");
		for(int i=0;i<256;i++) {
			if(i%20==0) {
				System.out.println();
			}
			System.out.print(isDigit[i]+"  ");
		}
		System.out.println("-----------------");
		System.out.println(toLower(10));
		System.out.println(10 & 0xff);
		
		byte []bys = new byte[] {49,50,50,51};
		System.out.println(parseLong(bys, 0, 4));
	}
}
