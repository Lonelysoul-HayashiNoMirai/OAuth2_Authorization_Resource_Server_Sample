package com.lonelysoul.sample.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequestMapping("${apiPrefix}/v1")
public class TestController {

    @GetMapping("/protected-string")
    public ResponseEntity<String> getProtectedString (){
        return ok ("protected-string");
    }
}
