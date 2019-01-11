package org.apache.tomcat.util.digester;

import java.io.File;
import java.io.IOException;

import org.xml.sax.SAXException;

public class EmployeeTest {
	
	public static void main(String[] args) throws IOException, SAXException {
		test1();
//		test2();
	}

	private static void test2() throws IOException, SAXException {
		String path = System.getProperty("user.dir")+File.separator+"etc";
		File file = new File(path,"employee2.xml");
		Digester digester = new Digester();
		//添加规则
		digester.addObjectCreate("employee", "org.apache.tomcat.util.digester.Employee");
		digester.addSetProperties("employee");
		digester.addObjectCreate("employee/office", "org.apache.tomcat.util.digester.Office");
		digester.addSetProperties("employee/office");
		digester.addSetNext("employee/office", "addOffice","org.apache.tomcat.util.digester.Office");
		//调用对象里面的方法
		digester.addCallMethod("employee", "printName");
		
		Employee employee = (Employee) digester.parse(file);
		System.out.println(employee.getFirstName());
		System.out.println(employee.getLastName());
	}
	
	
	private static void test1() throws IOException, SAXException {
		String path = System.getProperty("user.dir")+File.separator+"etc";
		File file = new File(path,"employee.xml");
		Digester digester = new Digester();
		//添加规则
		digester.addObjectCreate("employee", "org.apache.tomcat.util.digester.Employee","className");
		digester.addSetProperties("employee");
		//调用对象里面的方法
//		digester.addCallMethod("employee", "printName");
		
		Employee employee = (Employee) digester.parse(file);
		System.out.println(employee.getFirstName());
		System.out.println(employee.getLastName());
	}
	
}
