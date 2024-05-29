package app.secure.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HomeController {

    @GetMapping("/userinfo")
    public Principal user(Principal principal) {
        return principal;
    }
}
