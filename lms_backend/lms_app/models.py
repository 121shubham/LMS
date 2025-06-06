#lms_backend/lms_app/models.py

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)

    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('student', 'Student'),
        ('faculty', 'Faculty'),
        ('corporate', 'Corporate'),
        ('operation', 'Operation'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='student')
    mobile = models.CharField(max_length=15, blank=True, null=True)
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'auth_user'
        ordering = ['-created_at']
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return f"{self.username} ({self.role})"


# ───── New: Program and Enrollment ──────────────────────────────────────────

class Program(models.Model):
    """
    A Program groups multiple Courses; only enrolled students and assigned faculty can access.
    """
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='created_programs'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    # ─── which faculty “manage” this program ──────────────────────────────────
    faculty = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='programs_managed',
        limit_choices_to={'role': 'faculty'},
        blank=True
    )

    def __str__(self):
        return self.title


class Enrollment(models.Model):
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='enrollments'
    )
    program = models.ForeignKey(
        Program,
        on_delete=models.CASCADE,
        related_name='enrollments'
    )
    enrolled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('student', 'program')

    def __str__(self):
        return f"{self.student.username} in {self.program.title}"


# ───── Modify Course to link to Program ─────────────────────────────────────

class Course(models.Model):
    program = models.ForeignKey(
        Program,
        related_name='courses',
        on_delete=models.CASCADE,
        null=True,    # allow null for legacy data
        blank=True,   # allow blank in forms/admin for now
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='created_courses'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.program.title})"


# ───── New: Chapter ────────────────────────────────────────────────────────

class Chapter(models.Model):
    course = models.ForeignKey(
        Course,
        related_name='chapters',
        on_delete=models.CASCADE
    )
    title = models.CharField(max_length=200)
    order = models.PositiveIntegerField(
        help_text="Order within the course; smaller numbers appear first."
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['order']

    def __str__(self):
        return f"{self.course.title} – {self.title}"


# ───── Modify Content, Assignment, Quiz to refer to Chapter ────────────────

class Content(models.Model):
    chapter = models.ForeignKey(
        Chapter,
        related_name='contents',
        on_delete=models.CASCADE,
        null=True,    # allow legacy rows to remain valid
        blank=True,
    )
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='course_content/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.chapter})"


class Assignment(models.Model):
    chapter = models.ForeignKey(
        Chapter,
        related_name='assignments',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    due_date = models.DateTimeField()

    def __str__(self):
        return f"{self.title} ({self.chapter})"


class Quiz(models.Model):
    chapter = models.ForeignKey(
        Chapter,
        related_name='quizzes',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.chapter})"


class AssignmentSubmission(models.Model):
    assignment = models.ForeignKey(
        Assignment,
        related_name='submissions',
        on_delete=models.CASCADE
    )
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='assignment_submissions'
    )
    file = models.FileField(upload_to='assignment_submissions/')
    submitted_at = models.DateTimeField(auto_now_add=True)

    # ─── Faculty feedback fields ────────────────────────────────────────────
    feedback = models.TextField(blank=True, null=True)
    grade = models.IntegerField(blank=True, null=True)

    class Meta:
        unique_together = ('assignment', 'student')

    def __str__(self):
        return f"{self.student.username} – {self.assignment.title}"


# ───── MCQ models (unchanged except for linking via Chapter → Quiz) ─────────

class Question(models.Model):
    quiz = models.ForeignKey(
        Quiz,
        related_name='questions',
        on_delete=models.CASCADE
    )
    text = models.TextField()

    def __str__(self):
        return f"Q{self.id} ({self.quiz.title})"


class Choice(models.Model):
    question = models.ForeignKey(
        Question,
        related_name='choices',
        on_delete=models.CASCADE
    )
    text = models.CharField(max_length=300)
    is_correct = models.BooleanField(default=False)

    def __str__(self):
        return f"Choice {self.id} for Q{self.question.id}"


class StudentQuizAttempt(models.Model):
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='quiz_attempts',
        on_delete=models.CASCADE
    )
    quiz = models.ForeignKey(
        Quiz,
        related_name='attempts',
        on_delete=models.CASCADE
    )
    score = models.IntegerField()
    attempted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-attempted_at']
        unique_together = ('student', 'quiz')

    def __str__(self):
        return f"{self.student.username} on {self.quiz.title}: {self.score}"


class StudentAnswer(models.Model):
    attempt = models.ForeignKey(
        StudentQuizAttempt,
        related_name='answers',
        on_delete=models.CASCADE
    )
    question = models.ForeignKey(
        Question,
        related_name='student_answers',
        on_delete=models.CASCADE
    )
    selected_choice = models.ForeignKey(
        Choice,
        related_name='+',
        on_delete=models.CASCADE
    )

    def __str__(self):
        return f"Answer by {self.attempt.student.username} for Q{self.question.id}"
