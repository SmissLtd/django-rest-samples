from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import NotFound, ValidationError
from restApi.models import Users, Reports, Audios, ConditionSet
from django.http import HttpResponse
from datetime import date, timedelta, datetime
from zipfile import ZipFile
from io import BytesIO
from utils.permissions import CanDownloadReport
from utils.get_flags import get_flags
from django.db.models import Prefetch
from django.template.loader import get_template
from multiprocessing.pool import ThreadPool
from itertools import groupby
from utils.to_python import to_python
from configs.models import ConditionSet
import urllib.request
import xhtml2pdf.pisa as pisa
import base64
import json
import math
import pprint
import os
import json
import boto3
import os
import uuid

VARIANCE = 0.3
MUSCLE_VARIANCE = 0.6

EXPIRATION_DAYS_COUNT = 14

pp = pprint.PrettyPrinter(indent=4)


def check_expiration():
    for obj in Reports.objects.filter(created__lt=date.today()-timedelta(days=EXPIRATION_DAYS_COUNT)):
        obj.delete()


def _download_report(report_name):
    aws_key = os.environ['AWS_ACCESS_KEY']
    aws_secret = os.environ['AWS_SECRET_KEY']
    bucket_str = os.environ['AWS_REPORTS_CACHE']
    if not (aws_key and aws_secret and bucket_str):
        raise ValidationError(
            {"aws": ["Can't connect to aws, no credentials provided"]})
    if not report_name:
        raise ValidationError(
            {"report": ["Can't find report file"]}
        )
    s3 = boto3.client("s3", aws_access_key_id=aws_key,
                      aws_secret_access_key=aws_secret)
    report_file = s3.get_object(Bucket=bucket_str, Key=report_name)["Body"]
    return report_file.read()


def _upload_report(report, report_data):
    aws_key = os.environ['AWS_ACCESS_KEY']
    aws_secret = os.environ['AWS_SECRET_KEY']
    bucket_str = os.environ['AWS_REPORTS_CACHE']
    report_name = report.download_url
    created = report.created
    if not (aws_key and aws_secret and bucket_str):
        raise ValidationError(
            {"aws": ["Can't connect to aws, no credentials provided"]})
    s3 = boto3.client("s3", aws_access_key_id=aws_key,
                      aws_secret_access_key=aws_secret)
    expire_date = datetime.combine(
        created + timedelta(days=EXPIRATION_DAYS_COUNT), datetime.min.time())
    s3.put_object(Bucket=bucket_str, Key=report_name, Body=report_data,
                  Expires=expire_date)


def _get_user_or_404(pk=None):
    try:
        return Users.objects \
            .select_related('configuration_db__selected_version') \
            .prefetch_related('audios') \
            .prefetch_related(Prefetch('condition_db__versions')) \
            .get(pk=pk)
    except Exception as e:
        print(e)
        raise NotFound()


def _get_csv(audio):
    try:
        url = _normalizeURL(audio.csv_url)
        return f"Audio_{audio.id}.csv", urllib.request.urlopen(url).read()
    except Exception:
        return f"Audio_{audio.id}_error_csv.txt", f"file wasn't found {url}"


def _get_png(audio):
    try:
        url = _normalizeURL(audio.spectrum_url)
        return f"Audio_{audio.id}.png", urllib.request.urlopen(url).read()
    except Exception:
        return f"Audio_{audio.id}_error_png.txt", f"file wasn't found {url}"


def _get_json(audio):
    try:
        url = _normalizeURL(audio.json_url)
        return json.loads(urllib.request.urlopen(url).read().decode())
    except Exception:
        return None


def _get_report(audio, user, csv, png, should_print_tables, flags_db):
    template = get_template('./report_templates/individual.html')
    # template vars
    try:
        cond = ConditionSet.objects.get(pk=flags_db)
    except Exception:
        cond = user.condition_db

    config = user.configuration_db.selected_version
    try:
        imageBase64 = base64.encodebytes(png).decode("utf-8")
        prefixedimage = f"data:image/png;base64, {imageBase64}"
    except Exception:
        print(png)
        prefixedimage = ""
    #
    # VocalAnalysisData
    flags = get_flags(cond.versions.filter(
        version=cond.selected_version), audio)
    for flag in flags:
        flag["CORRELATION"] = flag["CORRELATION"].replace('_', ' ')
    # flags = audio.flags["result"]["flaggedData"]

    rows = audio.outlier

    def formatPrecision(num): return "{0:.2f}".format(float(num))
    for index, row in enumerate(rows):
        correlations = [
            flag for flag in flags if flag["Outlier_index"] == index]
        row["correlations"] = correlations
        row["frequency"] = formatPrecision(row["frequency"])
        row["decibelLevel"] = formatPrecision(row["decibelLevel"])
        row["brainWaveHarmonic"] = formatPrecision(row["brainWaveHarmonic"])
        row["variance"] = formatPrecision(row["variance"])
        row["reciprocal_BWH"] = formatPrecision(row["reciprocal_BWH"])
        row["reciprocal_Fundamental_BWH"] = formatPrecision(
            row["reciprocal_Fundamental_BWH"])

    pairs = []
    def getBWH(obj): return float(obj["brainWaveHarmonic"])
    for i, row in enumerate(rows):
        for j, second_row in enumerate(rows[i+1:]):
            if(math.fabs(getBWH(row) - getBWH(second_row)) <= VARIANCE):
                pairs.append([row, second_row])

    correlations = {}
    trended_data = audio.trended_data
    for key, group in groupby(flags, lambda x: x["CATEGORY"]):
        if key not in correlations:
            correlations[key] = []
        for x in group:
            if 'left' in x["CORRELATION"]:
                x["CORRELATION"] = ' '.join(
                    x["CORRELATION"].split(' ')[0:-1])
            if 'right' in x["CORRELATION"]:
                continue
            correlations[key].append({
                "correlation": x["CORRELATION"],
                "flag_direction": x["flag_direction"],
                "recommendations": x["RECOMMENDATIONS"]
            })

    highest_db = sorted(
        rows, key=lambda x: x["decibelLevel"], reverse=True)[:6]
    lowest_db = sorted(rows, key=lambda x: x["decibelLevel"])[:6]

    def format_rows(rows):
        return list(sorted(list(rows),
                           key=lambda x: x["brainWaveHarmonic"],
                           reverse=True))

    tables = [{
        "title": "All rows at or above 200 priority:",
        "rows": format_rows(filter(lambda x: x["priority"] > 200, rows))
    }, {
        "title": "Highest 6 results by decibel:",
        "rows": format_rows(highest_db)
    }, {
        "title": "Lowest 6 results by decibel:",
        "rows": format_rows(lowest_db)
    }]

    MUSCLE = 'Muscle'
    MUSCLE_RECOMMENDATIONS_LEN = 12
    RECOMMENDATIONS_LEN = 5
    for key in correlations.keys():
        correlations[key] = correlations[key][:RECOMMENDATIONS_LEN if not key ==
                                              MUSCLE else MUSCLE_RECOMMENDATIONS_LEN]

    html = template.render({
        "should_print_tables": should_print_tables,
        "cond_version": cond.id,
        "config_version": config.version,
        "full_name": f"{user.first_name} {user.last_name}",
        "user_id": user.id,
        "user_email": user.email,
        "record_date": audio.utc_unix_datetime,
        "record_num": audio.id,
        "record_title": audio.title,
        "min_freq": config.min_freq,
        "smoothing_factor": config.smoothing_factor,
        "max_freq": config.max_freq,
        "coherence_window_size": config.coherence_window_size,
        "window_size": config.window_size,
        "nutrient_variance": config.nutrient_variance,
        "fundamental_power": config.fundamental_power,
        "muscles_variance": config.muscles_variance,
        "running_mean_iteration_count": config.running_mean_iteration_count,
        "upper_bound_fs": config.upper_bound_fs,
        "outliers_passes": config.outliers_passes,
        "fs_density_factor": config.fs_density_factor,
        "image": prefixedimage,
        "tables": tables,
        "pairs_table": pairs,
        "correlations": correlations,
        "trended_data": trended_data
    })
    #
    pdf_bytes = BytesIO()
    pisa.pisaDocument(BytesIO(html.encode("UTF-8")), pdf_bytes)
    # return f"Audio_{audio.id}.txt", prefixedimage
    return f"Audio_{audio.id}.pdf", pdf_bytes.getvalue()


@api_view(['GET'])
@permission_classes((CanDownloadReport,))
def GenerateReport(request, userID):
    individual = request.query_params.get("only", None)
    should_print_tables = to_python(request.query_params.get("tables", True))
    flags_db = to_python(request.query_params.get("flags_db", None))
    user = _get_user_or_404(pk=userID)
    if individual is not None:
        try:
            included_in_report = [user.audios.get(pk=individual)]
        except Exception:
            raise NotFound()
    else:
        included_in_report = user.audios.all()

    try:
        audio = Audios.objects.get(pk=individual)
    except Exception:
        raise NotFound()
    try:
        condition = ConditionSet.objects.get(pk=flags_db)
    except Exception:
        condition = user.condition_db

    check_expiration()

    in_memory = BytesIO()
    is_new = False
    try:
        report = Reports.objects.get(audio_id=audio, condition_id=condition)
    except Exception:
        report = Reports.objects.create(audio_id=audio, condition_id=condition)
        download_url = 'report_{}_{}'. format(report.id, uuid.uuid4())
        setattr(report, 'download_url', download_url)
        report.save()
        is_new = True

    if is_new:
        with ZipFile(in_memory, mode="w") as zf:
            # if checkGroup(1, request):
            audios_to_analize = []
            for audio in included_in_report:
                audios_to_analize.append(audio)

            pool = ThreadPool(40)
            csvRes = pool.map(_get_csv, audios_to_analize)
            pngRes = pool.map(_get_png, audios_to_analize)
            pool.close()
            pool.join()
            for audio, csv, png in zip(audios_to_analize, csvRes, pngRes):
                zf.writestr(csv[0], csv[1])
                zf.writestr(png[0], png[1])
                zf.writestr(*_get_report(audio, user,
                                         csv[1], png[1], should_print_tables, flags_db))

        in_memory.seek(0)
        data = in_memory.read()
        _upload_report(report, data)
    else:
        in_memory.write(_download_report(report.download_url))

    in_memory.seek(0)
    data = in_memory.read()
    response = HttpResponse(data, content_type='application/zip')
    response['Content-Disposition'] = 'attachment; filename="report.zip"'
    return response
