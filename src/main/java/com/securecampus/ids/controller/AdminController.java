import com.securecampus.ids.entity.SecurityEvent;
import com.securecampus.ids.service.SecurityEventService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final SecurityEventService securityEventService;

    public AdminController(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @GetMapping("/test")
    public String adminTest() {
        return "Admin access granted";
    }

    @GetMapping("/events")
    public List<SecurityEvent> getAllEvents() {
        return securityEventService.getAllEvents();
    }
}