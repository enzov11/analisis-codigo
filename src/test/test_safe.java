// Versión segura del mismo código
public class test_safe {
    public static void main(String[] args) {
        String userInput = args[0];
        
        // FIX: Parameterized query
        String query = "SELECT * FROM users WHERE username = ?";
        PreparedStatement stmt = connection.prepareStatement(query);
        stmt.setString(1, userInput);  // Safe
        ResultSet rs = stmt.executeQuery();
        
        while (rs.next()) {
            System.out.println(rs.getString("username"));
        }
    }
}