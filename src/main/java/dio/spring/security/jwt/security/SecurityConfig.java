package dio.spring.security.jwt.security;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;


@Configuration
@ConfigurationProperties(prefix = "security.config")
public class SecurityConfig {
    public static String PREFIX;
    public static SecretKey SECRET_KEY; // mudar de String para SecretKey
    public static Long EXPIRATION;

    public void setPrefix(String prefix) {
        PREFIX = prefix;
    }

    // Aqui criamos a chave secreta no setter da "key"
    public void setKey(String key) {
        // Ignorar o valor vindo do application.properties e gerar chave segura
        SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    }

    public void setExpiration(Long expiration) {
        EXPIRATION = expiration;
    }
}
