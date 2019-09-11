from rest_framework.decorators import api_view, permission_classes, \
    parser_classes
from rest_framework.parsers import FileUploadParser
from rest_framework.exceptions import ValidationError
from utils.permissions import IsAdmin
from django.http import HttpResponse
from configs.models import ConditionSet, ConditionVersion
import csv
import io


@api_view(['POST'])
@permission_classes((IsAdmin,))
@parser_classes((FileUploadParser,))
def import_csv(request):
    csvfile = request.data.get('file', None)
    if csvfile is None:
        raise ValidationError(
            {"file": ["Not found"]})
    csvfile.seek(0)
    reader = csv.DictReader(io.StringIO(csvfile.read().decode('utf-8')))
    title = reader.fieldnames
    csv_rows = []
    for row in reader:
        csv_rows.extend([{title[i].strip().lower().replace(
            " ", "_"):row[title[i]] for i in range(len(title))}])

    c_set = ConditionSet.objects.create(selected_version=1)
    for row in csv_rows:
        row = {k: v for k, v in row.items() if v != ''}
        row['condition_db_id'] = c_set.id
        row['version'] = 1
        ConditionVersion.objects.create(**row)
    c_set.save()
    return HttpResponse(status=201)


def import_csv_for_testing():
    with open('utils/tests/Flags_Subset.csv') as csvfile:
        reader = csv.DictReader(csvfile)
        title = reader.fieldnames
        csv_rows = []
        for row in reader:
            csv_rows.extend([{title[i].strip().lower().replace(
                " ", "_"):row[title[i]] for i in range(len(title))}])

        c_set = ConditionSet.objects.create(selected_version=1)

        for index, row in enumerate(csv_rows):
            row = {k: v for k, v in row.items() if v != ''}
            row['condition_db_id'] = c_set.id
            row['version'] = index
            ConditionVersion.objects.create(**row)
