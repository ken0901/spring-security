package com.ken.app.controller;

import org.apache.coyote.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoController {

    private Logger logger = LoggerFactory.getLogger(getClass());
    private static final List<Todo> TODOS_LIST = List.of(new Todo("ken","Learn AWS"),
                                                new Todo("Katie", "Get AWS Certified"));

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos(){
        return TODOS_LIST;
    }

    @GetMapping("/users/{username}/todos")
    public Todo retrieveTodosForByUsername(@PathVariable String username){
        return TODOS_LIST.get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createTodosForByUsername(@PathVariable String username, @RequestBody Todo todo){
        logger.info("Create {} for {}", todo, username );
    }
}

record Todo (String username, String description) {}
