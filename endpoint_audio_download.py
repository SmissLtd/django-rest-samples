from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import ValidationError
from restApi.models import Audios
from django.shortcuts import get_object_or_404
from utils.permissions import IsAdmin, IsResearcher
from django.http import HttpResponse
from io import BytesIO
import boto3
import os


@api_view(['GET'])
@permission_classes((IsAdmin | IsResearcher,))
def get_audio(request, audioID):
    aws_key = os.environ['AWS_ACCESS_KEY']
    aws_secret = os.environ['AWS_SECRET_KEY']
    bucket_str = os.environ['AWS_BUCKET']
    if not (aws_key and aws_secret and bucket_str):
        raise ValidationError(
            {"aws": ["Can't connect to aws, no credentials provided"]})
    audio = get_object_or_404(Audios, pk=audioID)
    audio_name = audio.download_url
    if not audio_name:
        raise ValidationError(
            {"audio": ["Can't find audio file"]}
        )
    audio_name = audio_name.split(bucket_str)[1][1:]
    s3 = boto3.client("s3", aws_access_key_id=aws_key,
                      aws_secret_access_key=aws_secret)
    audio_file = s3.get_object(Bucket=bucket_str, Key=audio_name)["Body"]
    in_memory = BytesIO()
    in_memory.write(audio_file.read())
    in_memory.seek(0)
    data = in_memory.read()
    response = HttpResponse(data, content_type='audio/wav')
    response['Content-Disposition'] = f'attachment; filename="{audio_name}"'
    return response
