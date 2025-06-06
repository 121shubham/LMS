from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    CustomUser,
    Program,
    Enrollment,
    Course,
    Chapter,
    Content,
    Assignment,
    AssignmentSubmission,
    Quiz,
    Question,
    Choice,
    StudentQuizAttempt,
    StudentAnswer,
)


class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('username', 'email', 'role', 'is_approved', 'is_staff', 'is_active')
    list_filter = ('role', 'is_approved', 'is_staff', 'is_active')
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'is_approved', 'role', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role', 'is_approved', 'is_staff', 'is_active')}
        ),
    )
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)


admin.site.register(CustomUser, CustomUserAdmin)


@admin.register(Program)
class ProgramAdmin(admin.ModelAdmin):
    list_display = ('title', 'created_by', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('title',)
    filter_horizontal = ('faculty',)


@admin.register(Enrollment)
class EnrollmentAdmin(admin.ModelAdmin):
    list_display = ('student', 'program', 'enrolled_at')
    list_filter = ('program', 'enrolled_at')
    search_fields = ('student__username', 'program__title')


@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    list_display = ('title', 'program', 'created_by', 'created_at')
    list_filter = ('program', 'created_at')
    search_fields = ('title', 'program__title')


@admin.register(Chapter)
class ChapterAdmin(admin.ModelAdmin):
    list_display = ('title', 'course', 'order', 'created_at')
    list_filter = ('course', 'created_at')
    ordering = ('course', 'order')
    search_fields = ('title', 'course__title')


@admin.register(Content)
class ContentAdmin(admin.ModelAdmin):
    list_display = ('title', 'chapter', 'uploaded_at')
    list_filter = ('uploaded_at',)
    search_fields = ('title', 'chapter__title')


@admin.register(Assignment)
class AssignmentAdmin(admin.ModelAdmin):
    list_display = ('title', 'chapter', 'due_date')
    list_filter = ('due_date', 'chapter__course')
    search_fields = ('title', 'chapter__title')


@admin.register(AssignmentSubmission)
class AssignmentSubmissionAdmin(admin.ModelAdmin):
    list_display = ('assignment', 'student', 'submitted_at', 'grade')
    list_filter = ('assignment', 'submitted_at', 'grade')
    search_fields = ('student__username', 'assignment__title')


@admin.register(Quiz)
class QuizAdmin(admin.ModelAdmin):
    list_display = ('title', 'chapter', 'created_at')
    list_filter = ('created_at', 'chapter__course')
    search_fields = ('title', 'chapter__title')


@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ('id', 'quiz', 'text')
    list_filter = ('quiz',)
    search_fields = ('text', 'quiz__title')


@admin.register(Choice)
class ChoiceAdmin(admin.ModelAdmin):
    list_display = ('id', 'question', 'text', 'is_correct')
    list_filter = ('is_correct', 'question__quiz')
    search_fields = ('text', 'question__text')


@admin.register(StudentQuizAttempt)
class AttemptAdmin(admin.ModelAdmin):
    list_display = ('student', 'quiz', 'score', 'attempted_at')
    list_filter = ('quiz', 'student')
    search_fields = ('student__username', 'quiz__title')


@admin.register(StudentAnswer)
class AnswerAdmin(admin.ModelAdmin):
    list_display = ('attempt', 'question', 'selected_choice')
    list_filter = ('attempt', 'question')
    search_fields = ('attempt__student__username', 'question__text', 'selected_choice__text')
