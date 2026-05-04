package com.securecampus.ids.service;

import com.securecampus.ids.entity.SecurityEvent;
import com.securecampus.ids.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SecurityEventService {

    private final SecurityEventRepository repository;

    public SecurityEventService(SecurityEventRepository repository) {
        this.repository = repository;
    }

    public void logEvent(String eventType, String username, String ip, String description) {

        SecurityEvent event = new SecurityEvent();
        event.setEventType(eventType);
        event.setUsername(username);
        event.setIpAddress(ip);
        event.setDescription(description);

        repository.save(event);
    }
    public List<SecurityEvent> getAllEvents() {
        return repository.findAll();
    }
}