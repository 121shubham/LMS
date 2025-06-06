from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    api_signup,
    api_login,
    get_csrf,
    leaderboard,
    UserListView,
    UserDetailView,
    ProgramViewSet,
    EnrollmentViewSet,
    CourseViewSet,
    ChapterViewSet,
    ContentViewSet,
    AssignmentViewSet,
    AssignmentSubmissionViewSet,
    QuizViewSet,
    QuestionViewSet,
    ChoiceViewSet,
    StudentQuizAttemptViewSet,
    stream_content,
    course_progress,
)

router = DefaultRouter()
router.register(r'programs', ProgramViewSet, basename='program')
router.register(r'enrollments', EnrollmentViewSet, basename='enrollment')
router.register(r'courses', CourseViewSet, basename='course')
router.register(r'chapters', ChapterViewSet, basename='chapter')
router.register(r'contents', ContentViewSet, basename='content')
router.register(r'assignments', AssignmentViewSet, basename='assignment')
router.register(r'submissions', AssignmentSubmissionViewSet, basename='submission')
router.register(r'quizzes', QuizViewSet, basename='quiz')
router.register(r'questions', QuestionViewSet, basename='question')
router.register(r'choices', ChoiceViewSet, basename='choice')
router.register(r'quiz_attempts', StudentQuizAttemptViewSet, basename='attempt')

urlpatterns = [
    path('get-csrf/', get_csrf, name='get-csrf'),
    path('signup/', api_signup, name='api_signup'),
    path('login/', api_login, name='api_login'),
    path('leaderboard/', leaderboard, name='leaderboard'),

    # Explicit user list/detail endpoints
    path('users/', UserListView.as_view(), name='user-list'),
    path('users/<int:pk>/', UserDetailView.as_view(), name='user-detail'),

    # Stream content / course progress
    path('stream-content/<int:content_id>/', stream_content, name='stream_content'),
    path('course-progress/<int:course_id>/', course_progress, name='course_progress'),

    # Include all ViewSets registered above
    path('', include(router.urls)),
]
