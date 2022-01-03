package dev.niangfils.springsec;

import dev.niangfils.springsec.domain.Role;
import dev.niangfils.springsec.domain.User;
import dev.niangfils.springsec.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecApplication implements CommandLineRunner {
    @Autowired
    private UserService userService;
    @Bean
    public  static PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    public SpringSecApplication(UserService userService) {
        this.userService = userService;
    }


    public static void main(String[] args) {
        SpringApplication.run(SpringSecApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        userService.saveRole(new Role(null, "USER_ROLE"));
        userService.saveRole(new Role(null, "MANAGER_ROLE"));
        userService.saveRole(new Role(null, "ADMIN_ROLE"));
        userService.saveRole(new Role(null, "SUPER_ADMIN_ROLE"));
        userService.saveUser(new User(null, "Omar NIANG", "omar", "1234", new ArrayList<>()));
        userService.saveUser(new User(null, "Amadou SALL", "amadou", "1234", new ArrayList<>()));
        userService.saveUser(new User(null, "Abdou Xudos NIANg", "abdou", "1234", new ArrayList<>()));
        userService.saveUser(new User(null, "Rane WADE", "rane", "1234", new ArrayList<>()));
        userService.addRoleToUser("omar", "SUPER_ADMIN_ROLE");
        userService.addRoleToUser("omar", "ADMIN_ROLE");
        userService.addRoleToUser("amadou", "USER_ROLE");
        userService.addRoleToUser("abdou", "MANAGER_ROLE");
        userService.addRoleToUser("rane", "USER_ROLE");

    }
}
