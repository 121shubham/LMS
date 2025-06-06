from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import (
    CustomUser, Program, Enrollment, Course, Chapter,
    Content, Assignment, AssignmentSubmission, Quiz,
    Question, Choice, StudentQuizAttempt, StudentAnswer
)

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'mobile', 'first_name', 'last_name',
            'role', 'is_approved', 'is_staff', 'is_active',
            'date_joined', 'last_login'
        ]
        read_only_fields = ['date_joined', 'last_login']


# ───── Program Serializer ───────────────────────────────────────────────────

class ProgramSerializer(serializers.ModelSerializer):
    faculty = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=User.objects.filter(role='faculty'),
        required=False
    )
    is_enrolled = serializers.SerializerMethodField()

    class Meta:
        model = Program
        fields = [
            'id', 'title', 'description', 'created_by', 'created_at',
            'faculty', 'is_enrolled'
        ]
        read_only_fields = ['created_by', 'created_at', 'is_enrolled']

    def get_is_enrolled(self, obj):
        request = self.context.get('request', None)
        if not request or request.user.is_anonymous:
            return False
        return Enrollment.objects.filter(student=request.user, program=obj).exists()

    def create(self, validated_data):
        faculty_data = validated_data.pop('faculty', [])
        program = Program.objects.create(**validated_data)
        if faculty_data:
            program.faculty.set(faculty_data)
        return program

    def update(self, instance, validated_data):
        faculty_data = validated_data.pop('faculty', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if faculty_data is not None:
            instance.faculty.set(faculty_data)
        instance.save()
        return instance


class EnrollmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Enrollment
        fields = ['id', 'student', 'program', 'enrolled_at']
        read_only_fields = ['enrolled_at']


class CourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ['id', 'program', 'title', 'description', 'created_by', 'created_at']
        read_only_fields = ['created_by', 'created_at']


class ChapterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chapter
        fields = ['id', 'course', 'title', 'order', 'created_at']
        read_only_fields = ['created_at']


class ContentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Content
        fields = ['id', 'chapter', 'title', 'file', 'uploaded_at']
        read_only_fields = ['uploaded_at']


class AssignmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Assignment
        fields = ['id', 'chapter', 'title', 'description', 'due_date']


class AssignmentSubmissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssignmentSubmission
        fields = [
            'id', 'assignment', 'student', 'file',
            'submitted_at', 'feedback', 'grade'
        ]
        read_only_fields = ['submitted_at']


class QuizSerializer(serializers.ModelSerializer):
    class Meta:
        model = Quiz
        fields = ['id', 'chapter', 'title', 'description', 'created_at']
        read_only_fields = ['created_at']


class ChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ['id', 'text', 'is_correct']
        read_only_fields = ['id']


class QuestionSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True)

    class Meta:
        model = Question
        fields = ['id', 'quiz', 'text', 'choices']
        read_only_fields = ['id']

    def create(self, validated_data):
        choices_data = validated_data.pop('choices', [])
        question = Question.objects.create(**validated_data)
        for ch in choices_data:
            Choice.objects.create(question=question, **ch)
        return question

    def update(self, instance, validated_data):
        instance.text = validated_data.get('text', instance.text)
        instance.save()
        if 'choices' in validated_data:
            choices_data = validated_data.pop('choices')
            instance.choices.all().delete()
            for ch in choices_data:
                Choice.objects.create(question=instance, **ch)
        return instance


class StudentAnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentAnswer
        fields = ['question', 'selected_choice']


class StudentQuizAttemptSerializer(serializers.ModelSerializer):
    answers = StudentAnswerSerializer(many=True)

    class Meta:
        model = StudentQuizAttempt
        fields = ['id', 'student', 'quiz', 'score', 'attempted_at', 'answers']
        read_only_fields = ['id', 'score', 'attempted_at']

    def create(self, validated_data):
        answers_data = validated_data.pop('answers', [])
        student = validated_data['student']
        quiz = validated_data['quiz']
        total_score = 0
        attempt = StudentQuizAttempt.objects.create(student=student, quiz=quiz, score=0)

        for ans in answers_data:
            question = ans['question']
            chosen = ans['selected_choice']
            StudentAnswer.objects.create(attempt=attempt, question=question, selected_choice=chosen)
            if chosen.is_correct:
                total_score += 1

        attempt.score = total_score
        attempt.save()
        return attempt


class LeaderboardSerializer(serializers.Serializer):
    username = serializers.CharField()
    total_score = serializers.IntegerField()
