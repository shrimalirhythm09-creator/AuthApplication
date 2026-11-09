package com.auth.auth_app.entity;
import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "user_id")
    private UUID id;
    @Column(unique = true)
    private String email;
    private String name;
    private String password;
    private String image;
    private boolean enable = true;
    private Instant createdAt = Instant.now();
    private Instant updatedAt = Instant.now();
    private String gender;
    private Provider provider = Provider.LOCAL;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles",joinColumns = @JoinColumn(name = "user_id")
            ,inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    @PrePersist
    protected void onCreate(){
        Instant now = Instant.now();

        if (createdAt == null) createdAt =now;
        updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        if (createdAt == null) {
            updatedAt = Instant.now();
        }
    }



}
