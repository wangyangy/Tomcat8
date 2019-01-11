package org.apache.tomcat.util.digester;

import java.util.ArrayList;

public class Employee {
	private String firstName;
	private String lastName;
	
	private ArrayList<Office> arrayList = new ArrayList<>();
	
	
	public Employee() {
		super();
		System.out.println("createing Employee");
	}
	public String getFirstName() {
		return firstName;
	}
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	public String getLastName() {
		return lastName;
	}
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	
	public void printName() {
		System.out.println(this.firstName+"."+this.lastName);
	}
	
	public void addOffice(Office office) {
		this.arrayList.add(office);
	}
	public ArrayList<Office> getOffice() {
		return arrayList;
	}
	
	
	
}
