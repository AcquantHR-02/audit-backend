package com.AcquantHR.AuditManagementSystem.ServiceImpl;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.AcquantHR.AuditManagementSystem.Entity.Audit;
import com.AcquantHR.AuditManagementSystem.Entity.User;
import com.AcquantHR.AuditManagementSystem.Exception.ResourceNotFoundException;
import com.AcquantHR.AuditManagementSystem.Exception.UnauthorizedActionException;
import com.AcquantHR.AuditManagementSystem.Repo.AuditRepository;
import com.AcquantHR.AuditManagementSystem.Repo.UserRepository;
import com.AcquantHR.AuditManagementSystem.Service.AuditService;

@Service
public class AuditServiceImpl implements AuditService {

    private final AuditRepository auditRepository;
    private final UserRepository userRepository;

    public AuditServiceImpl(
            AuditRepository auditRepository,
            UserRepository userRepository) {

        this.auditRepository = auditRepository;
        this.userRepository = userRepository;
    }

    // =========================
    // CREATE AUDIT
    // =========================

    @Override
    public Audit createAudit(Audit audit) {

        if (audit.getAuditor() == null ||
                audit.getAuditor().getId() == null) {

            throw new ResourceNotFoundException(
                    "Auditor ID is required");
        }

        Long auditorId = audit.getAuditor().getId();

        User auditor = userRepository.findById(auditorId)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "Auditor not found with id: " + auditorId));

        if (auditor.getRole() == null ||
                !"AUDITOR".equalsIgnoreCase(
                        auditor.getRole().getName())) {

            throw new UnauthorizedActionException(
                    "Selected user is not an auditor");
        }

        audit.setAuditor(auditor);

        return auditRepository.save(audit);
    }

    // =========================
    // GET AUDIT BY ID
    // =========================

    @Override
    public Audit getAuditById(Long id) {

        Audit audit = auditRepository.findById(id)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "Audit not found with id: " + id));

        Authentication authentication =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication();

        String email = authentication.getName();

        User loggedInUser = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "User not found"));

        // ADMIN can view any audit
        if (loggedInUser.getRole() != null &&
                "ADMIN".equalsIgnoreCase(
                        loggedInUser.getRole().getName())) {

            return audit;
        }

        // AUDITOR can view only assigned audit
        if (loggedInUser.getRole() != null &&
                "AUDITOR".equalsIgnoreCase(
                        loggedInUser.getRole().getName())) {

            if (audit.getAuditor() == null ||
                    !audit.getAuditor().getId()
                            .equals(loggedInUser.getId())) {

                throw new UnauthorizedActionException(
                        "This audit is not assigned to you");
            }

            return audit;
        }

        throw new UnauthorizedActionException(
                "You are not authorized to view this audit");
    }

    // =========================
    // GET ALL AUDITS
    // =========================

    @Override
    public List<Audit> getAllAudits() {

        Authentication authentication =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication();

        String email = authentication.getName();

        User loggedInUser = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "User not found"));

        // =========================
        // ADMIN
        // =========================

        if (loggedInUser.getRole() != null &&
                "ADMIN".equalsIgnoreCase(
                        loggedInUser.getRole().getName())) {

            return auditRepository.findAll();
        }

        // =========================
        // AUDITOR
        // =========================

        if (loggedInUser.getRole() != null &&
                "AUDITOR".equalsIgnoreCase(
                        loggedInUser.getRole().getName())) {

            return auditRepository.findByAuditor(loggedInUser);
        }

        // =========================
        // OTHER ROLES
        // =========================

        throw new UnauthorizedActionException(
                "You are not authorized to view audits");
    }

    // =========================
    // UPDATE AUDIT
    // =========================

    @Override
    public Audit updateAudit(Long id, Audit audit) {

        Audit existingAudit = getAuditById(id);

        existingAudit.setTitle(audit.getTitle());
        existingAudit.setDescription(audit.getDescription());
        existingAudit.setStartDate(audit.getStartDate());
        existingAudit.setEndDate(audit.getEndDate());
        existingAudit.setStatus(audit.getStatus());
        existingAudit.setAuditor(audit.getAuditor());

        return auditRepository.save(existingAudit);
    }
    // =========================
    // DELETE AUDIT
    // =========================

    @Override
    public void deleteAudit(Long id) {

        if (!auditRepository.existsById(id)) {

            throw new ResourceNotFoundException(
                    "Audit not found with id: " + id);
        }

        auditRepository.deleteById(id);
    }

    // =========================
    // GET BY STATUS
    // =========================

    @Override
    public List<Audit> getAuditsByStatus(String status) {

        return auditRepository.findByStatus(status);
    }

    // =========================
    // ASSIGN AUDITOR
    // =========================

    @Override
    public Audit assignAuditor(
            Long auditId,
            Long auditorId) {

        Audit audit = auditRepository.findById(auditId)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "Audit not found with id: " + auditId));

        User auditor = userRepository.findById(auditorId)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "Auditor not found with id: " + auditorId));

        if (auditor.getRole() == null ||
                !"AUDITOR".equalsIgnoreCase(
                        auditor.getRole().getName())) {

            throw new UnauthorizedActionException(
                    "Selected user is not an auditor");
        }

        audit.setAuditor(auditor);

        return auditRepository.save(audit);
    }

    // =========================
    // GET AUDITS BY AUDITOR
    // =========================

    @Override
    public List<Audit> getAuditsByAuditor(Long auditorId) {

        User auditor = userRepository.findById(auditorId)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "Auditor not found with id: " + auditorId));

        return auditRepository.findByAuditor(auditor);
    }
}