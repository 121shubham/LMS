#lms_backend/lms_app/views.py

from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.http import JsonResponse, FileResponse, Http404, HttpResponse
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.shortcuts import get_object_or_404

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics, permissions, filters, viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.parsers import MultiPartParser
from django.middleware.csrf import get_token
from rest_framework.exceptions import PermissionDenied

import json
import pandas as pd

from .models import (
    CustomUser, Program, Enrollment, Course, Chapter,
    Content, Assignment, AssignmentSubmission, Quiz,
    Question, Choice, StudentQuizAttempt, StudentAnswer
)

from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import (
    UserSerializer, ProgramSerializer, EnrollmentSerializer,
    CourseSerializer, ChapterSerializer, ContentSerializer,
    AssignmentSerializer, AssignmentSubmissionSerializer, QuizSerializer,
    QuestionSerializer, ChoiceSerializer, StudentQuizAttemptSerializer, LeaderboardSerializer,CustomTokenObtainPairSerializer
)

User = get_user_model()


# ─────────────────────────────────────────────────────────────────────────────
#                         CSRF / Legacy Signup/Login
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([AllowAny])
def get_csrf(request):
    """
    Endpoint to set (and return) a fresh CSRF token cookie.
    """
    response = HttpResponse("CSRF cookie set")
    response["X-CSRFToken"] = get_token(request)
    return response

class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Uses CustomTokenObtainPairSerializer to enforce that the 'role' sent in the payload
    matches user.role in the database. If mismatch, returns 400 with {"role": ["Invalid role for this user."]}.
    """
    serializer_class = CustomTokenObtainPairSerializer


@csrf_exempt
def api_signup(request):
    """
    Legacy session-based signup (kept for backward compatibility).
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)
    try:
        data = json.loads(request.body)
        username = data.get('username')
        mobile = data.get('mobile')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
    except Exception:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    if not all([username, mobile, email, password, role]):
        return JsonResponse({'error': 'All fields are required'}, status=400)

    try:
        user = CustomUser.objects.create_user(
            username=username,
            mobile=mobile,
            email=email,
            password=password,
            role=role
        )
        if role.lower() == 'admin':
            user.is_staff = True
            user.is_superuser = True
        else:
            user.is_staff = True
        user.save()
        return JsonResponse({'message': 'User created successfully'}, status=201)
    except IntegrityError as e:
        if 'username' in str(e):
            return JsonResponse({'error': 'Username already exists.'}, status=400)
        elif 'email' in str(e):
            return JsonResponse({'error': 'Email already exists.'}, status=400)
        else:
            return JsonResponse({'error': 'Could not create account.'}, status=400)


@csrf_exempt
def api_login(request):
    """
    Legacy session-based login (kept for backward compatibility).
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
    except Exception:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    if not all([username, password, role]):
        return JsonResponse({'error': 'Username, password, and role required'}, status=400)

    try:
        user = CustomUser.objects.get(username__iexact=username, role__iexact=role)
        if not user.is_approved:
            return JsonResponse({'error': 'Account is not approved yet.'}, status=403)
        if user.check_password(password):
            login(request, user)
            return JsonResponse({
                'message': 'Login successful',
                'role': user.role,
                'username': user.username,
                'is_approved': user.is_approved,
                'is_staff': user.is_staff,
                'id': user.id
            }, status=200)
        else:
            return JsonResponse({'error': 'Invalid password'}, status=401)
    except CustomUser.DoesNotExist:
        return JsonResponse({'error': 'Invalid username or password'}, status=401)
    





# ─────────────────────────────────────────────────────────────────────────────
#                              User Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class UserListView(generics.ListAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['role', 'is_approved', 'is_staff', 'is_active']
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering_fields = ['date_joined', 'last_login']


class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


# ─────────────────────────────────────────────────────────────────────────────
#                        Program & Enrollment Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class ProgramViewSet(viewsets.ModelViewSet):
    queryset = Program.objects.all()
    serializer_class = ProgramSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        # Only admin can create programs
        if not self.request.user.is_staff or self.request.user.role != 'admin':
            raise PermissionDenied("Only admins can create programs.")
        serializer.save(created_by=self.request.user)

    def perform_update(self, serializer):
        if not self.request.user.is_staff or self.request.user.role != 'admin':
            raise PermissionDenied("Only admins can update programs.")
        serializer.save()


class EnrollmentViewSet(viewsets.ModelViewSet):
    queryset = Enrollment.objects.all()
    serializer_class = EnrollmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # Students only see their own enrollments; admin/faculty see all
        if user.role == 'student':
            return Enrollment.objects.filter(student=user)
        return Enrollment.objects.all()

    def perform_create(self, serializer):
        user = self.request.user
        # Only admin/faculty can enroll a student
        if not (user.role in ['admin', 'faculty']):
            raise PermissionDenied("Only Admin or Faculty can enroll students.")
        # Prevent duplicate enrollment (unique_together handles this, but just in case)
        student = serializer.validated_data['student']
        program = serializer.validated_data['program']
        if Enrollment.objects.filter(student=student, program=program).exists():
            raise serializers.ValidationError("Student already enrolled in this program.")
        serializer.save()


# ─────────────────────────────────────────────────────────────────────────────
#                          Course / Chapter Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class CourseViewSet(viewsets.ModelViewSet):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_permissions(self):
        # You could customize permission logic here if needed
        return [permissions.IsAuthenticated()]

    def perform_create(self, serializer):
        program = serializer.validated_data.get('program')
        user = self.request.user
        # Only admin or assigned faculty for that program can create a course
        if user.role == 'admin' or program.faculty.filter(id=user.id).exists():
            serializer.save(created_by=user)
        else:
            raise PermissionDenied("Not allowed to create course for this program.")

    def perform_update(self, serializer):
        program = serializer.instance.program
        user = self.request.user
        if user.role == 'admin' or program.faculty.filter(id=user.id).exists():
            serializer.save()
        else:
            raise PermissionDenied("Not allowed to update this course.")


class ChapterViewSet(viewsets.ModelViewSet):
    queryset = Chapter.objects.all()
    serializer_class = ChapterSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        Optionally filter by course via ?course=<course_id>.
        """
        qs = super().get_queryset()
        course_id = self.request.query_params.get('course')
        if course_id:
            qs = qs.filter(course__id=course_id)
        return qs

    def perform_create(self, serializer):
        course = serializer.validated_data.get('course')
        user = self.request.user
        # Only admin or program-faculty can create chapter
        if user.role == 'admin' or course.program.faculty.filter(id=user.id).exists():
            serializer.save()
        else:
            raise PermissionDenied("Not allowed to create chapter for this course.")

    def perform_update(self, serializer):
        course = serializer.instance.course
        user = self.request.user
        if user.role == 'admin' or course.program.faculty.filter(id=user.id).exists():
            serializer.save()
        else:
            raise PermissionDenied("Not allowed to update this chapter.")


# ─────────────────────────────────────────────────────────────────────────────
#                              Content Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class ContentViewSet(viewsets.ModelViewSet):
    queryset = Content.objects.all()
    serializer_class = ContentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        chapter = serializer.validated_data.get('chapter')
        user = self.request.user
        # Only admin or program-faculty can upload content
        if user.role == 'admin' or chapter.course.program.faculty.filter(id=user.id).exists():
            serializer.save()
        else:
            raise PermissionDenied("Not allowed to upload content to this chapter.")

    def perform_update(self, serializer):
        chapter = serializer.instance.chapter
        user = self.request.user
        if user.role == 'admin' or chapter.course.program.faculty.filter(id=user.id).exists():
            serializer.save()
        else:
            raise PermissionDenied("Not allowed to update this content.")


# ─────────────────────────────────────────────────────────────────────────────
#                      Assignment & Submission Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class AssignmentViewSet(viewsets.ModelViewSet):
    queryset = Assignment.objects.all()
    serializer_class = AssignmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        Optionally filter by chapter via ?chapter=<chapter_id>.
        """
        qs = super().get_queryset()
        chap_id = self.request.query_params.get('chapter')
        if chap_id:
            qs = qs.filter(chapter__id=chap_id)
        return qs

    def perform_create(self, serializer):
        chapter = serializer.validated_data.get('chapter')
        user = self.request.user
        # Only admin or program-faculty can create assignment
        if user.role == 'admin' or chapter.course.program.faculty.filter(id=user.id).exists():
            serializer.save()
        else:
            raise PermissionDenied("Not allowed to create assignment for this chapter.")

    def perform_update(self, serializer):
        chapter = serializer.instance.chapter
        user = self.request.user
        if user.role == 'admin' or chapter.course.program.faculty.filter(id=user.id).exists():
            serializer.save()
        else:
            raise PermissionDenied("Not allowed to update this assignment.")


class AssignmentSubmissionViewSet(viewsets.ModelViewSet):
    queryset = AssignmentSubmission.objects.all()
    serializer_class = AssignmentSubmissionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # Students see only their own submissions; admin/faculty see all
        if user.role == 'student':
            return AssignmentSubmission.objects.filter(student=user)
        if user.role == 'faculty':
            return AssignmentSubmission.objects.filter(
                assignment__chapter__course__program__faculty=user
            )
        return AssignmentSubmission.objects.all()

    def perform_create(self, serializer):
        user = self.request.user
        assignment = serializer.validated_data.get('assignment')
        program = assignment.chapter.course.program
        # Student may only submit if enrolled in that program
        if user.role == 'student' and Enrollment.objects.filter(student=user, program=program).exists():
            serializer.save(student=user)
        else:
            raise PermissionDenied("Not allowed to submit for this assignment.")

    def perform_update(self, serializer):
        user = self.request.user
        instance = serializer.instance
        assignment = instance.assignment
        program = assignment.chapter.course.program

        # Case 1: Student updating own submission (only before grading)
        if user.role == 'student' and instance.student == user:
            if instance.grade is None:
                serializer.save()
            else:
                raise PermissionDenied("Cannot update after grading.")
        # Case 2: Faculty/Admin updating feedback/grade
        elif user.role == 'faculty' and program.faculty.filter(id=user.id).exists():
            serializer.save()
        elif user.role == 'admin':
            serializer.save()
        else:
            raise PermissionDenied("Not allowed to update this submission.")


# ─────────────────────────────────────────────────────────────────────────────
#                         Quiz / Question Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class QuizViewSet(viewsets.ModelViewSet):
    queryset = Quiz.objects.all()
    serializer_class = QuizSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        Optionally filter by chapter via ?chapter=<chapter_id>.
        """
        qs = super().get_queryset()
        chap_id = self.request.query_params.get('chapter')
        if chap_id:
            qs = qs.filter(chapter__id=chap_id)
        return qs

    @action(detail=True, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def questions(self, request, pk=None):
        quiz = self.get_object()
        program = quiz.chapter.course.program
        user = request.user

        # Only admin or assigned faculty or enrolled student may fetch questions
        if user.role == 'student':
            if not Enrollment.objects.filter(student=user, program=program).exists():
                raise PermissionDenied("Not enrolled in this program.")
        elif user.role == 'faculty':
            if not program.faculty.filter(id=user.id).exists():
                raise PermissionDenied("Not assigned to this program.")
        # Admin bypasses check

        qs = quiz.questions.all()
        serializer = QuestionSerializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def bulk_import(self, request, pk=None):
        quiz = self.get_object()
        program = quiz.chapter.course.program
        user = request.user

        # Only admin or program-faculty can bulk import
        if not (user.role == 'admin' or program.faculty.filter(id=user.id).exists()):
            raise PermissionDenied("Not allowed to import questions for this quiz.")

        if 'file' not in request.FILES:
            return Response({'error': 'No file uploaded.'}, status=status.HTTP_400_BAD_REQUEST)
        excel_file = request.FILES['file']
        try:
            df = pd.read_excel(excel_file)
        except Exception as e:
            return Response({'error': f'Invalid Excel file: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        required_cols = {'question', 'choice1', 'choice2', 'choice3', 'choice4', 'correct_choice_index'}
        if not required_cols.issubset(set(df.columns)):
            return Response({'error': f'Excel must contain columns: {required_cols}'}, status=status.HTTP_400_BAD_REQUEST)

        created_count = 0
        for _, row in df.iterrows():
            q_text = row['question']
            question = Question.objects.create(quiz=quiz, text=q_text)
            choices = [
                {'text': row['choice1'], 'is_correct': (row['correct_choice_index'] == 1)},
                {'text': row['choice2'], 'is_correct': (row['correct_choice_index'] == 2)},
                {'text': row['choice3'], 'is_correct': (row['correct_choice_index'] == 3)},
                {'text': row['choice4'], 'is_correct': (row['correct_choice_index'] == 4)},
            ]
            for ch in choices:
                Choice.objects.create(question=question, **ch)
            created_count += 1

        return Response({'imported': created_count}, status=status.HTTP_201_CREATED)


class QuestionViewSet(viewsets.ModelViewSet):
    queryset = Question.objects.all()
    serializer_class = QuestionSerializer
    permission_classes = [permissions.IsAuthenticated]
    # Only admin/faculty of that program should be allowed to CRUD; we rely on QuizViewSet.bulk_import for create.


class ChoiceViewSet(viewsets.ModelViewSet):
    queryset = Choice.objects.all()
    serializer_class = ChoiceSerializer
    permission_classes = [permissions.IsAuthenticated]


class StudentQuizAttemptViewSet(viewsets.ModelViewSet):
    queryset = StudentQuizAttempt.objects.all()
    serializer_class = StudentQuizAttemptSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'student':
            return StudentQuizAttempt.objects.filter(student=user)
        elif user.role == 'faculty':
            return StudentQuizAttempt.objects.filter(quiz__chapter__course__program__faculty=user)
        else:
            return StudentQuizAttempt.objects.all()

    def perform_create(self, serializer):
        student = serializer.validated_data.get('student')
        quiz = serializer.validated_data.get('quiz')
        program = quiz.chapter.course.program
        user = self.request.user

        # Only a student may submit their own attempt if enrolled:
        if user.role == 'student':
            if user != student:
                raise PermissionDenied("Cannot attempt on behalf of someone else.")
            if not Enrollment.objects.filter(student=user, program=program).exists():
                raise PermissionDenied("Not enrolled in this program.")
            # Score calculation handled in serializer
            serializer.save()
        else:
            raise PermissionDenied("Only students can submit quiz attempts.")


# ─────────────────────────────────────────────────────────────────────────────
#                        Leaderboard / Utility Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def leaderboard(request):
    """
    GET /api/leaderboard/?program=<id>  OR  /api/leaderboard/?course=<id>  OR  /api/leaderboard/?quiz=<id>
    Returns a list of { username, total_score } ordered by score descending.
    We include both quiz scores and assignment grades in total_score.
    """
    program_id = request.query_params.get('program')
    course_id = request.query_params.get('course')
    quiz_id = request.query_params.get('quiz')

    def build_leaderboard_for_attempts(attempts, include_assignments=False, program_filter=None):
        data = {}
        # Sum quiz scores per student
        for a in attempts:
            uname = a.student.username
            data[uname] = data.get(uname, 0) + a.score

        # Include assignment grades if requested
        if include_assignments and program_filter:
            from django.db.models import Q
            enrolled_students = Enrollment.objects.filter(program__id=program_filter).values_list('student', flat=True)
            asubmissions = AssignmentSubmission.objects.filter(
                assignment__chapter__course__program__id=program_filter,
                student__in=enrolled_students,
                grade__isnull=False
            )
            for sub in asubmissions:
                uname = sub.student.username
                data[uname] = data.get(uname, 0) + (sub.grade or 0)

        leaderboard_data = sorted(
            [{'username': k, 'total_score': v} for k, v in data.items()],
            key=lambda x: x['total_score'], reverse=True
        )
        return leaderboard_data

    if quiz_id:
        attempts = StudentQuizAttempt.objects.filter(quiz__id=quiz_id)
        # For a single quiz, take highest per student
        per_student_max = {}
        for a in attempts:
            uname = a.student.username
            per_student_max[uname] = max(per_student_max.get(uname, 0), a.score)
        leaderboard_data = sorted(
            [{'username': k, 'total_score': v} for k, v in per_student_max.items()],
            key=lambda x: x['total_score'], reverse=True
        )
        serializer = LeaderboardSerializer(leaderboard_data, many=True)
        return Response(serializer.data)

    elif course_id:
        from django.db.models import Sum
        quizzes = Quiz.objects.filter(chapter__course__id=course_id)
        attempts = StudentQuizAttempt.objects.filter(quiz__in=quizzes)
        data = {}
        for a in attempts:
            uname = a.student.username
            data[uname] = data.get(uname, 0) + a.score

        # Include assignment grades from this course
        enrolled_students = Enrollment.objects.filter(
            program__in=quizzes.values_list('chapter__course__program', flat=True)
        ).values_list('student', flat=True)
        asubmissions = AssignmentSubmission.objects.filter(
            assignment__chapter__course__id=course_id,
            student__in=enrolled_students,
            grade__isnull=False
        )
        for sub in asubmissions:
            uname = sub.student.username
            data[uname] = data.get(uname, 0) + (sub.grade or 0)

        leaderboard_data = sorted(
            [{'username': k, 'total_score': v} for k, v in data.items()],
            key=lambda x: x['total_score'], reverse=True
        )
        serializer = LeaderboardSerializer(leaderboard_data, many=True)
        return Response(serializer.data)

    elif program_id:
        from django.db.models import Sum
        enrolled_students = Enrollment.objects.filter(
            program__id=program_id
        ).values_list('student', flat=True)

        quizzes = Quiz.objects.filter(chapter__course__program__id=program_id)
        attempts = StudentQuizAttempt.objects.filter(quiz__in=quizzes, student__in=enrolled_students)

        leaderboard_data = build_leaderboard_for_attempts(
            attempts,
            include_assignments=True,
            program_filter=program_id
        )
        serializer = LeaderboardSerializer(leaderboard_data, many=True)
        return Response(serializer.data)

    else:
        return Response({'error': 'Provide ?program=<id> or ?course=<id> or ?quiz=<id>'}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def stream_content(request, content_id):
    """
    Stream a Content.file only if the requesting user is enrolled in that
    content's program (or is faculty/admin).
    """
    content = get_object_or_404(Content, id=content_id)
    program = content.chapter.course.program
    user = request.user

    # Check enrollment (admin and faculty bypass)
    if user.role == 'student':
        if not Enrollment.objects.filter(student=user, program=program).exists():
            return Response({'error': 'Not enrolled in this program.'}, status=status.HTTP_403_FORBIDDEN)

    try:
        return FileResponse(open(content.file.path, 'rb'), content_type='application/octet-stream')
    except Exception:
        raise Http404


@csrf_exempt
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def course_progress(request, course_id):
    """
    Returns how many chapters completed, assignments submitted, quizzes attempted.
    """
    user = request.user
    chapters = Chapter.objects.filter(course__id=course_id)
    total_chapters = chapters.count()

    completed_quizzes = StudentQuizAttempt.objects.filter(
        student=user,
        quiz__chapter__course__id=course_id
    ).values_list('quiz__chapter', flat=True).distinct().count()

    submitted_assignments = AssignmentSubmission.objects.filter(
        student=user,
        assignment__chapter__course__id=course_id
    ).values_list('assignment__chapter', flat=True).distinct().count()

    return Response({
        'total_chapters': total_chapters,
        'chapters_with_quiz_completed': completed_quizzes,
        'chapters_with_assignment_submitted': submitted_assignments,
    })
