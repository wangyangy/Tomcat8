package mytest;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

public class TestJNDI {
	
	public static void main(String[] args) throws Exception {
		Context initContext = new InitialContext();
		DataSource ds = (DataSource)initContext.lookup("java:/comp/env/jdbc/test");
		Connection conn = ds.getConnection();
		String sql = "select * from stu";
		PreparedStatement st = conn.prepareStatement(sql);
		ResultSet rs = st.executeQuery();
		while(rs.next()){
			System.out.println("name:"+rs.getString(2)+" age:"+rs.getInt(3)+"<br>");
		}
		if(rs!=null){
			try{
				rs.close();
			}catch (Exception e) {
				e.printStackTrace();
			}
			rs = null;
		}
		if(st!=null){
			try{
				st.close();
			}catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
}