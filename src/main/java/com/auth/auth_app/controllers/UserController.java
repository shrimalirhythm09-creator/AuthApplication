package com.auth.auth_app.controllers;

import com.auth.auth_app.dto.UserDto;
import com.auth.auth_app.entity.User;
import com.auth.auth_app.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@AllArgsConstructor
@RestController
@RequestMapping("/api/v1/users")

public class UserController {

    private final UserService userService;

    @PostMapping
    public ResponseEntity<UserDto> createUser(@RequestBody UserDto userDto){
        return ResponseEntity.status(201).body(userService.createUser(userDto));
    }

    @GetMapping
    public ResponseEntity<Iterable<UserDto>> getAllUsers(){
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<UserDto> getUserByEmail(@RequestBody String email){
       return ResponseEntity.ok(userService.getUserByEmail(email));
    }

    @DeleteMapping("/{userId}")
    public void deleteUser(@PathVariable("userId")String userId ){
        userService.deleteUser(userId);
    }

    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUser(@RequestBody UserDto userDto,@PathVariable("userId") String userId){
        return ResponseEntity.ok(userService.updateUser(userDto,userId));
    }

    @GetMapping("{userId}")
    public ResponseEntity<UserDto> getUserById(@PathVariable("userId") String userId){
        return ResponseEntity.ok(userService.getUserById(userId));
    }
}
