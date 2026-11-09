package com.auth.auth_app.service.impl;

import com.auth.auth_app.dto.UserDto;
import com.auth.auth_app.entity.Provider;
import com.auth.auth_app.entity.User;
import com.auth.auth_app.exception.ResourceNotFoundException;
import com.auth.auth_app.helper.UserHelper;
import com.auth.auth_app.repositary.UserRepositary;
import com.auth.auth_app.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {


    private final UserRepositary userRepositary;
    private final ModelMapper modelMapper;


    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        if (userDto.getEmail() == null || userDto.getEmail().isBlank()){
            throw new IllegalArgumentException("Email is Required");
        }
        if (userRepositary.existsByEmail(userDto.getEmail())){
            throw new IllegalArgumentException("Email Already exists");
        }
        User user = modelMapper.map(userDto,User.class);
        user.setProvider(userDto.getProvider()!=null?userDto.getProvider(): Provider.LOCAL);

        User savedUser =  userRepositary.save(user);

        return modelMapper.map(savedUser,UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {
     User user =  userRepositary.findByEmail(email).
             orElseThrow(() -> new ResourceNotFoundException("User not found with given emailId"));

        return modelMapper.map(user,UserDto.class);
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uId = UserHelper.parseUUID(userId);
        User existingUser = userRepositary.findById(uId).
                orElseThrow(() -> new ResourceNotFoundException("User not found"));
        if (userDto.getName()!=null) existingUser.setName(userDto.getName());
        if (userDto.getImage()!=null)existingUser.setImage(userDto.getImage());
        if (userDto.getProvider()!=null) existingUser.setProvider(userDto.getProvider());
        if (userDto.getPassword()!=null) existingUser.setPassword(userDto.getPassword());

        existingUser.setEnable(userDto.isEnable());

      User updatedUser = userRepositary.save(existingUser);
        return modelMapper.map(updatedUser,UserDto.class);
    }

    @Override
    public void deleteUser(String userId) {
        UUID uId = UserHelper.parseUUID(userId);
     User user =  userRepositary.findById(uId).
             orElseThrow(() -> new ResourceNotFoundException("User not found"));
        userRepositary.delete(user);
    }

    @Override
    public UserDto getUserById(String userId) {
      User  user = userRepositary.findById(UserHelper.
                parseUUID(userId)).
              orElseThrow(() -> new ResourceNotFoundException("User not found with given id"));
        return modelMapper.map(user,UserDto.class);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return userRepositary
                .findAll()
                .stream()
                .map(user -> modelMapper.map(user,UserDto.class))
                .toList();
    }
}
