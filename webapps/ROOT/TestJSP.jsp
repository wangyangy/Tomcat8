<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="javax.naming.*" %>
<%@ page import="java.sql.*" %>
<%@ page import="javax.sql.*" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
</head>
<body>
<h2>Results</h2>
<%
Context initContext = new InitialContext();
DataSource ds = (DataSource)initContext.lookup("java:/comp/env/jdbc/test");
Connection conn = ds.getConnection();
Connection conn = ds.getConnection();
String sql = "select * from stu";
PreparedStatement st = conn.prepareStatement(sql);
ResultSet rs = st.executeQuery();
while(rs.next()){
out.println("name:"+rs.getString(2)+" age:"+rs.getInt(3)+"<br>");
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
 
if(conn!=null){
try{
conn.close();
}catch (Exception e) {
e.printStackTrace();
}
}
%>
</body>
</html>
