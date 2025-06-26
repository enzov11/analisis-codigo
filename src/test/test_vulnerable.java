// CWE-89: SQL Injection
public class test_vulnerable {
    public static void main(String[] args) {
        String userInput = args[0];
        
        // POTENTIAL FLAW: SQL Injection
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);  // Vulnerable line
        
        while (rs.next()) {
            System.out.println(rs.getString("username"));
        }
    }
}