# Part 084: SQL Injection ใน Java Spring

## ภาพรวม

Spring Boot, JDBC, JPA/Hibernate - บั่งเสี่ยงและป้องกัน

**ขั้นตอนที่ 1331-1345**

---

## 1331. JDBC PreparedStatement

```java
import java.sql.*;

public class UserRepository {
    private final Connection conn;
    
    // VULNERABLE: concatenation
    public User findUserVulnerable(String username) throws SQLException {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);  // SQL injection!
        if (rs.next()) {
            return mapRow(rs);
        }
        return null;
    }
    
    // SECURE: PreparedStatement
    public User findUserSafe(String username) throws SQLException {
        String sql = "SELECT * FROM users WHERE username = ?";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, username);  // ใช้ index 1 สำหรับ ? ตัวแรก
        ResultSet rs = stmt.executeQuery();
        if (rs.next()) {
            return mapRow(rs);
        }
        return null;
    }
    
    // SECURE: Multiple params
    public User login(String username, String password) throws SQLException {
        String sql = "SELECT * FROM users WHERE username = ? AND password_hash = ?";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, username);
        stmt.setString(2, hashPassword(password));
        ResultSet rs = stmt.executeQuery();
        return rs.next() ? mapRow(rs) : null;
    }
}
```

---

## 1332. Spring JDBC Template

```java
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

@Repository
public class OrderRepository {
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // VULNERABLE: string format
    public List<Order> findByStatusVuln(String status) {
        return jdbcTemplate.query(
            String.format("SELECT * FROM orders WHERE status = '%s'", status),
            orderRowMapper
        );
    }
    
    // SECURE: varargs params
    public List<Order> findByStatusSafe(String status) {
        return jdbcTemplate.query(
            "SELECT * FROM orders WHERE status = ?",
            orderRowMapper,
            status  // ส่งเป็น vararg
        );
    }
    
    // Named params ด้วย NamedParameterJdbcTemplate
    public Order findByIdNamed(int orderId) {
        NamedParameterJdbcTemplate namedJdbc = new NamedParameterJdbcTemplate(jdbcTemplate);
        Map<String, Object> params = Map.of("orderId", orderId);
        return namedJdbc.queryForObject(
            "SELECT * FROM orders WHERE id = :orderId",
            params,
            orderRowMapper
        );
    }
}
```

---

## 1333. JPA/Hibernate JPQL

```java
import javax.persistence.*;

@Repository
public class ProductRepository {
    @PersistenceContext
    private EntityManager em;
    
    // VULNERABLE: JPQL concat
    public List<Product> searchVuln(String name) {
        return em.createQuery(
            "FROM Product p WHERE p.name LIKE '%" + name + "%'",
            Product.class
        ).getResultList();
    }
    
    // SECURE: named parameter
    public List<Product> searchSafe(String name) {
        return em.createQuery(
            "FROM Product p WHERE p.name LIKE :name",
            Product.class
        )
        .setParameter("name", "%" + name + "%")
        .getResultList();
    }
    
    // SECURE: Spring Data JPA repository
    // interface ProductRepo extends JpaRepository<Product, Long> {
    //     List<Product> findByNameContaining(String name); // safe!
    // }
}
```

---

## 1334. Spring Security + SQLi

```java
// Spring Security custom UserDetailsService - ต้อง secure
@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // SECURE: parameterized query
        List<Map<String, Object>> users = jdbcTemplate.queryForList(
            "SELECT * FROM users WHERE username = ?",
            username
        );
        
        if (users.isEmpty()) {
            throw new UsernameNotFoundException("User not found");
        }
        
        Map<String, Object> user = users.get(0);
        return User.builder()
            .username((String) user.get("username"))
            .password((String) user.get("password"))
            .roles((String) user.get("role"))
            .build();
    }
}
```

---

## สรุป

Java Spring SQLi:
- **JDBC** - PreparedStatement + setString()
- **JdbcTemplate** - varargs params
- **JPQL** - `:named` parameters
- **Spring Data** - `findByX()` safe by default

---

*Part 084 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*
