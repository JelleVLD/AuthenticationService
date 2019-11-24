package be.thomasmore.auth;

import java.util.Arrays;
import java.util.List;

import be.thomasmore.auth.model.AppUser;
import be.thomasmore.auth.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service   // It has to be annotated with @Service.
public class UserDetailServiceImpl implements UserDetailsService  {

    @Autowired
    private BCryptPasswordEncoder encoder;
    @Autowired
    private AppUserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(!repository.existsAppUserByUsernameEquals("admin")){
            final List<AppUser> users = Arrays.asList(
                    new AppUser(1,"username1", encoder.encode("password1"), "ADMIN"),
                    new AppUser(2,"username2", encoder.encode("password2"), "USER")
            );
            repository.insert(users);
        }

        if(repository.existsAppUserByUsernameEquals(username)) {
            AppUser appUser = repository.findByUsernameEquals(username);
            List<GrantedAuthority> grantedAuthorities = AuthorityUtils
                    .commaSeparatedStringToAuthorityList("ROLE_" + appUser.getRole());
            return new User(appUser.getUsername(), appUser.getPassword(), grantedAuthorities);
        }

        throw new UsernameNotFoundException("Username: " + username + " not found");
    }




}
