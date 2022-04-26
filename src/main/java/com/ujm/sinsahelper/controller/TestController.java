package com.ujm.sinsahelper.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TestController {

    @GetMapping(value = "/getSearch")
    public void getSearch() {
        System.out.println("possible");
    }

}
